import asyncio
import json
import re
import uuid
import time
import secrets
import base64
import mimetypes
import random
import traceback
from collections import defaultdict
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timezone, timedelta

from platformdirs import user_data_dir
import uvicorn
from camoufox.async_api import AsyncCamoufox
from fastapi import FastAPI, HTTPException, Depends, status, Form, Request, Response
from starlette.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.security import APIKeyHeader

import httpx
import tiktoken
from curl_cffi.requests import AsyncSession
from curl_cffi.requests.exceptions import HTTPError, Timeout, RequestException as RequestsError

# ============================================================
# CONFIGURATION
# ============================================================
# Set to True for detailed logging, False for minimal logging
DEBUG = False

# Port to run the server on
PORT = 8081

# Chunk size for splitting large prompts (characters)
CHUNK_SIZE = 140000

# Max chunks per session before rotating identity.
# Set to 1 to revert to "Old Architecture" (New Session every chunk) - Most Reliable
# Set to 3 to use "Hybrid Architecture" (Rotates every 3 chunks) - Stealthier
CHUNK_ROTATION_LIMIT = 3

# Set to True to reuse the same LMArena session ID for the same API Key + Model.
# This mimics "Direct Chat" behavior and can help bypass "New Session" rate limits (422/429).
STICKY_SESSIONS = True
# ============================================================

def debug_print(*args, **kwargs):
    """Print debug messages only if DEBUG is True"""
    if DEBUG:
        print(*args, **kwargs)

# Custom UUIDv7 implementation (using correct Unix epoch)
def uuid7():
    """
    Generate a UUIDv7 using Unix epoch (milliseconds since 1970-01-01)
    matching the browser's implementation.
    """
    timestamp_ms = int(time.time() * 1000)
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)
    
    uuid_int = timestamp_ms << 80
    uuid_int |= (0x7000 | rand_a) << 64
    uuid_int |= (0x8000000000000000 | rand_b)
    
    hex_str = f"{uuid_int:032x}"
    return f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"

# Image upload helper functions
async def upload_image_to_lmarena(image_data: bytes, mime_type: str, filename: str) -> Optional[tuple]:
    """
    Upload an image to LMArena R2 storage and return the key and download URL.
    
    Args:
        image_data: Binary image data
        mime_type: MIME type of the image (e.g., 'image/png')
        filename: Original filename for the image
    
    Returns:
        Tuple of (key, download_url) if successful, or None if upload fails
    """
    try:
        # Validate inputs
        if not image_data:
            debug_print("❌ Image data is empty")
            return None
        
        if not mime_type or not mime_type.startswith('image/'):
            debug_print(f"❌ Invalid MIME type: {mime_type}")
            return None
        
        # Step 1: Request upload URL
        debug_print(f"📤 Step 1: Requesting upload URL for {filename}")
        
        # Prepare headers for Next.js Server Action
        request_headers = get_request_headers()
        request_headers.update({
            "Accept": "text/x-component",
            "Content-Type": "text/plain;charset=UTF-8",
            "Next-Action": "70cb393626e05a5f0ce7dcb46977c36c139fa85f91",
            "Referer": "https://lmarena.ai/?mode=direct",
        })
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    "https://lmarena.ai/?mode=direct",
                    headers=request_headers,
                    content=json.dumps([filename, mime_type]),
                    timeout=30.0
                )
                response.raise_for_status()
            except httpx.TimeoutException:
                debug_print("❌ Timeout while requesting upload URL")
                return None
            except httpx.HTTPError as e:
                debug_print(f"❌ HTTP error while requesting upload URL: {e}")
                return None
            
            # Parse response - format: 0:{...}\n1:{...}\n
            try:
                lines = response.text.strip().split('\n')
                upload_data = None
                for line in lines:
                    if line.startswith('1:'):
                        upload_data = json.loads(line[2:])
                        break
                
                if not upload_data or not upload_data.get('success'):
                    debug_print(f"❌ Failed to get upload URL: {response.text[:200]}")
                    return None
                
                upload_url = upload_data['data']['uploadUrl']
                key = upload_data['data']['key']
                debug_print(f"✅ Got upload URL and key: {key}")
            except (json.JSONDecodeError, KeyError, IndexError) as e:
                debug_print(f"❌ Failed to parse upload URL response: {e}")
                return None
            
            # Step 2: Upload image to R2 storage
            debug_print(f"📤 Step 2: Uploading image to R2 storage ({len(image_data)} bytes)")
            try:
                response = await client.put(
                    upload_url,
                    content=image_data,
                    headers={"Content-Type": mime_type},
                    timeout=60.0
                )
                response.raise_for_status()
                debug_print(f"✅ Image uploaded successfully")
            except httpx.TimeoutException:
                debug_print("❌ Timeout while uploading image to R2 storage")
                return None
            except httpx.HTTPError as e:
                debug_print(f"❌ HTTP error while uploading image: {e}")
                return None
            
            # Step 3: Get signed download URL (uses different Next-Action)
            debug_print(f"📤 Step 3: Requesting signed download URL")
            request_headers_step3 = request_headers.copy()
            request_headers_step3["Next-Action"] = "6064c365792a3eaf40a60a874b327fe031ea6f22d7"
            
            try:
                response = await client.post(
                    "https://lmarena.ai/?mode=direct",
                    headers=request_headers_step3,
                    content=json.dumps([key]),
                    timeout=30.0
                )
                response.raise_for_status()
            except httpx.TimeoutException:
                debug_print("❌ Timeout while requesting download URL")
                return None
            except httpx.HTTPError as e:
                debug_print(f"❌ HTTP error while requesting download URL: {e}")
                return None
            
            # Parse response
            try:
                lines = response.text.strip().split('\n')
                download_data = None
                for line in lines:
                    if line.startswith('1:'):
                        download_data = json.loads(line[2:])
                        break
                
                if not download_data or not download_data.get('success'):
                    debug_print(f"❌ Failed to get download URL: {response.text[:200]}")
                    return None
                
                download_url = download_data['data']['url']
                debug_print(f"✅ Got signed download URL: {download_url[:100]}...")
                return (key, download_url)
            except (json.JSONDecodeError, KeyError, IndexError) as e:
                debug_print(f"❌ Failed to parse download URL response: {e}")
                return None
            
    except Exception as e:
        debug_print(f"❌ Unexpected error uploading image: {type(e).__name__}: {e}")
        return None

async def process_message_content(content, model_capabilities: dict) -> tuple[str, List[dict]]:
    """
    Process message content, handle images if present and model supports them.
    
    Args:
        content: Message content (string or list of content parts)
        model_capabilities: Model's capability dictionary
    
    Returns:
        Tuple of (text_content, experimental_attachments)
    """
    # Check if model supports image input
    supports_images = model_capabilities.get('inputCapabilities', {}).get('image', False)
    
    # If content is a string, return it as-is
    if isinstance(content, str):
        return content, []
    
    # If content is a list (OpenAI format with multiple parts)
    if isinstance(content, list):
        text_parts = []
        attachments = []
        
        for part in content:
            if isinstance(part, dict):
                if part.get('type') == 'text':
                    text_parts.append(part.get('text', ''))
                    
                elif part.get('type') == 'image_url' and supports_images:
                    image_url = part.get('image_url', {})
                    if isinstance(image_url, dict):
                        url = image_url.get('url', '')
                    else:
                        url = image_url
                    
                    # Handle base64-encoded images
                    if url.startswith('data:'):
                        # Format: data:image/png;base64,iVBORw0KGgo...
                        try:
                            # Validate and parse data URI
                            if ',' not in url:
                                debug_print(f"❌ Invalid data URI format (no comma separator)")
                                continue
                            
                            header, data = url.split(',', 1)
                            
                            # Parse MIME type
                            if ';' not in header or ':' not in header:
                                debug_print(f"❌ Invalid data URI header format")
                                continue
                            
                            mime_type = header.split(';')[0].split(':')[1]
                            
                            # Validate MIME type
                            if not mime_type.startswith('image/'):
                                debug_print(f"❌ Invalid MIME type: {mime_type}")
                                continue
                            
                            # Decode base64
                            try:
                                image_data = base64.b64decode(data)
                            except Exception as e:
                                debug_print(f"❌ Failed to decode base64 data: {e}")
                                continue
                            
                            # Validate image size (max 10MB)
                            if len(image_data) > 10 * 1024 * 1024:
                                debug_print(f"❌ Image too large: {len(image_data)} bytes (max 10MB)")
                                continue
                            
                            # Generate filename
                            ext = mimetypes.guess_extension(mime_type) or '.png'
                            filename = f"upload-{uuid.uuid4()}{ext}"
                            
                            debug_print(f"🖼️  Processing base64 image: {filename}, size: {len(image_data)} bytes")
                            
                            # Upload to LMArena
                            upload_result = await upload_image_to_lmarena(image_data, mime_type, filename)
                            
                            if upload_result:
                                key, download_url = upload_result
                                # Add as attachment in LMArena format
                                attachments.append({
                                    "name": key,
                                    "contentType": mime_type,
                                    "url": download_url
                                })
                                debug_print(f"✅ Image uploaded and added to attachments")
                            else:
                                debug_print(f"⚠️  Failed to upload image, skipping")
                        except Exception as e:
                            debug_print(f"❌ Unexpected error processing base64 image: {type(e).__name__}: {e}")
                    
                    # Handle URL images (direct URLs)
                    elif url.startswith('http://') or url.startswith('https://'):
                        # For external URLs, we'd need to download and re-upload
                        # For now, skip this case
                        debug_print(f"⚠️  External image URLs not yet supported: {url[:100]}")
                        
                elif part.get('type') == 'image_url' and not supports_images:
                    debug_print(f"⚠️  Image provided but model doesn't support images")
        
        # Combine text parts
        text_content = '\n'.join(text_parts).strip()
        return text_content, attachments
    
    # Fallback
    return str(content), []

app = FastAPI()

# --- Constants & Global State ---
CONFIG_FILE = "config.json"
MODELS_FILE = "models.json"
API_KEY_HEADER = APIKeyHeader(name="Authorization")

# In-memory stores
# { "api_key": { "conversation_id": session_data } }
chat_sessions: Dict[str, Dict[str, dict]] = defaultdict(dict)
# { "session_id": "username" }
dashboard_sessions = {}
# { "api_key": [timestamp1, timestamp2, ...] }
api_key_usage = defaultdict(list)
# { "model_id": count }
model_usage_stats = defaultdict(int)
# { "api_key_model": "session_id" }
sticky_session_ids = {}

# --- Helper Functions ---

def get_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        config = {}

    # Ensure default keys exist
    config.setdefault("password", "admin")
    config.setdefault("auth_token", "")
    config.setdefault("cf_clearance", "")
    config.setdefault("user_agent", "")      # <--- NEW
    config.setdefault("cookie_string", "")   # <--- NEW
    config.setdefault("api_keys", [])
    config.setdefault("usage_stats", {})
    
    return config

def load_usage_stats():
    """Load usage stats from config into memory"""
    global model_usage_stats
    config = get_config()
    model_usage_stats = defaultdict(int, config.get("usage_stats", {}))

def save_config(config):
    # Persist in-memory stats to the config dict before saving
    config["usage_stats"] = dict(model_usage_stats)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def get_models():
    try:
        with open(MODELS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_models(models):
    with open(MODELS_FILE, "w") as f:
        json.dump(models, f, indent=2)

# Add a global token index tracker
current_token_index = 0
token_lock = asyncio.Lock()

# Global counter for active generations to prevent premature refreshing
active_generations = 0

def get_request_headers():
    global current_token_index
    
    config = get_config()
    auth_tokens = config.get("auth_tokens", [])

    # Fallback to single token for backwards compatibility
    if not auth_tokens:
        raise HTTPException(status_code=500, detail="No arena auth tokens configured.")
    
    # Round-robin token selection
    token = auth_tokens[current_token_index % len(auth_tokens)]
    current_token_index = (current_token_index + 1) % len(auth_tokens)

    print(f"Using {current_token_index+1}. token." )
    
    # Use captured User-Agent or fallback
    user_agent = config.get("user_agent")
    if not user_agent:
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    # Use full captured cookie string if available
    cookie_string = config.get("cookie_string", "")
    
    # Construct final cookie header
    if cookie_string:
        # Append our auth token to the browser's cookies
        final_cookies = f"{cookie_string}; arena-auth-prod-v1={token}"
    else:
        # Fallback to old method
        cf_clearance = config.get("cf_clearance", "").strip()
        final_cookies = f"cf_clearance={cf_clearance}; arena-auth-prod-v1={token}"

    return {
        "Content-Type": "application/json",
        "User-Agent": user_agent,
        "Cookie": final_cookies,
        "Referer": "https://lmarena.ai/",
        "Origin": "https://lmarena.ai",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Priority": "u=1, i"
    }

# --- Dashboard Authentication ---

async def get_current_session(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id and session_id in dashboard_sessions:
        return dashboard_sessions[session_id]
    return None

# --- API Key Authentication & Rate Limiting ---

async def rate_limit_api_key(key: str = Depends(API_KEY_HEADER)):
    if not key.startswith("Bearer "):
        raise HTTPException(
            status_code=401, 
            detail="Invalid Authorization header. Expected 'Bearer YOUR_API_KEY'"
        )
    
    # Remove "Bearer " prefix and strip whitespace
    api_key_str = key[7:].strip()
    print(f"DEBUG: Received API Key: '{api_key_str}'")
    config = get_config()
    
    key_data = next((k for k in config["api_keys"] if k["key"] == api_key_str), None)
    if not key_data:
        raise HTTPException(status_code=401, detail="Invalid API Key.")

    # Rate Limiting
    rpm_limit = key_data.get("rpm", 60)
    rpd_limit = key_data.get("rpd", 10000)  # Default daily limit
    current_time = time.time()
    
    # Clean up old timestamps (older than 24 hours)
    api_key_usage[api_key_str] = [t for t in api_key_usage[api_key_str] if current_time - t < 86400]

    # Check RPM (last 60 seconds)
    requests_last_minute = [t for t in api_key_usage[api_key_str] if current_time - t < 60]
    if len(requests_last_minute) >= rpm_limit:
        # Calculate seconds until oldest request expires (60 seconds window)
        oldest_timestamp = min(requests_last_minute)
        retry_after = int(60 - (current_time - oldest_timestamp))
        retry_after = max(1, retry_after)  # At least 1 second
        
        raise HTTPException(
            status_code=429,
            detail="Rate limit (RPM) exceeded. Please try again later.",
            headers={"Retry-After": str(retry_after)}
        )

    # Check RPD (last 24 hours)
    if len(api_key_usage[api_key_str]) >= rpd_limit:
        # Calculate seconds until oldest request expires (24 hours window)
        oldest_timestamp = min(api_key_usage[api_key_str])
        retry_after = int(86400 - (current_time - oldest_timestamp))
        retry_after = max(1, retry_after)
        
        raise HTTPException(
            status_code=429,
            detail="Rate limit (Daily) exceeded. Please try again later.",
            headers={"Retry-After": str(retry_after)}
        )
        
    api_key_usage[api_key_str].append(current_time)
    
    return key_data

# --- Core Logic ---

global_browser = None
global_page = None

async def get_initial_data():
    global global_browser, global_page
    print("Starting initial data retrieval...")
    
    # Close previous page if it exists
    if global_page:
        try:
            print("♻️ Closing previous page...")
            await global_page.close()
        except Exception as e:
            print(f"⚠️ Failed to close previous page: {e}")
    
    try:
        # Enable geoip to look more legitimate
        # async with AsyncCamoufox(headless=True, geoip=True) as browser:
        if True: # Preserve indentation level
            if global_browser is None:
                print("🚀 Initializing global browser instance...")
                global_browser = await AsyncCamoufox(headless=True, geoip=True).__aenter__()
            browser = global_browser

            page = await browser.new_page()
            global_page = page

            # --- STEALTH UPGRADE START ---
            # 1. Randomize Viewport (Desktop sizes)
            width = random.randint(1366, 1920)
            height = random.randint(768, 1080)
            await page.set_viewport_size({"width": width, "height": height})
            
            # 2. Set Realistic Headers
            await page.set_extra_http_headers({
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-User": "?1"
            })

            # 3. Forcefully remove webdriver property
            await page.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
            """)
            
            # --- STEALTH UPGRADE END ---
            
            # 1. Capture the specific User-Agent Camoufox is using
            user_agent = await page.evaluate("navigator.userAgent")
            print(f"🕵️ Camoufox User Agent: {user_agent[:50]}...")
            
            print("Navigating to lmarena.ai...")

            # Random delay before navigation
            await asyncio.sleep(random.uniform(1, 3))

            try:
                # 4. Use Google Referer & Increase Timeout
                await page.goto(
                    "https://lmarena.ai/", 
                    wait_until="domcontentloaded", 
                    timeout=90000, # 90 seconds timeout
                    referer="https://www.google.com/"
                )
            except Exception as e:
                # 5. Continue even if timeout occurs (Challenge might still be loaded)
                print(f"⚠️ Navigation timeout/warning (continuing to check for challenge): {e}")

            print("Waiting for Cloudflare challenge to complete...")
            try:
                # Wait a bit for the challenge to load
                await asyncio.sleep(3 + random.random())
                
                # 2. Humanize: Random mouse movements
                await page.mouse.move(random.randint(100, 500), random.randint(100, 500))
                await asyncio.sleep(0.5)
                await page.mouse.move(random.randint(100, 500), random.randint(100, 500), steps=10)
        
                # Look for Cloudflare Turnstile checkbox/widget
                print("🕵️ Looking for Cloudflare Turnstile iframe (scanning frames)...")
                turnstile_frame = None
                
                # Poll for the frame in page.frames
                for i in range(10): # Poll for 10 seconds
                    for frame in page.frames:
                        if "challenges.cloudflare.com" in frame.url and "turnstile" in frame.url:
                            turnstile_frame = frame
                            break
                    if turnstile_frame:
                        break
                    await asyncio.sleep(1)
                
                if turnstile_frame:
                    print(f"✅ Found Turnstile frame: {turnstile_frame.url}")
                    await asyncio.sleep(random.uniform(2.0, 4.0)) # Wait longer for content to render
                    
                    # DEBUG: Print frame content to understand structure
                    try:
                        frame_content = await turnstile_frame.content()
                        print(f"🔍 Turnstile Frame Content Preview: {frame_content[:300]}...")
                    except Exception as e:
                        print(f"⚠️ Could not read frame content: {e}")

                    # Try to find the checkbox inside the frame
                    checkbox = None
                    # Expanded selectors including generic ones
                    checkbox_selectors = [
                        'input[type="checkbox"]', 
                        '.cb-lb', 
                        'label', 
                        '.ctp-checkbox-label',
                        '#challenge-stage',
                        '.big-button'
                    ]
                    
                    for sel in checkbox_selectors:
                        try:
                            checkbox = await turnstile_frame.query_selector(sel)
                            if checkbox:
                                print(f"✅ Found element in frame using selector: {sel}")
                                break
                        except:
                            pass
                    
                    if checkbox:
                        # Get coordinates
                        cb_box = await checkbox.bounding_box()
                        if cb_box:
                            # Calculate center
                            x = cb_box['x'] + cb_box['width'] / 2
                            y = cb_box['y'] + cb_box['height'] / 2
                            
                            print(f"🖱️ Moving mouse to element at ({int(x)}, {int(y)})...")
                            await page.mouse.move(x, y, steps=random.randint(15, 25))
                            await asyncio.sleep(random.uniform(0.3, 0.6))
                            
                            print("🖱️ Clicking element...")
                            await page.mouse.down()
                            await asyncio.sleep(random.uniform(0.05, 0.15))
                            await page.mouse.up()
                        else:
                            print("⚠️ Element found but has no bounding box. Clicking blindly.")
                            await checkbox.click()
                    else:
                        print("⚠️ No specific checkbox element found. Attempting to click the frame body.")
                        try:
                            body = await turnstile_frame.query_selector('body')
                            if body:
                                await body.click()
                                print("🖱️ Clicked frame body.")
                        except Exception as e:
                            print(f"⚠️ Failed to click frame body: {e}")

                        # Fallback: Try to click the center of the iframe element on the main page
                        try:
                            iframes = await page.query_selector_all('iframe')
                            print(f"🔍 Found {len(iframes)} iframes on main page.")
                            
                            target_iframe = None
                            for iframe_el in iframes:
                                src = await iframe_el.get_attribute('src')
                                name = await iframe_el.get_attribute('name')
                                if (src and "challenges.cloudflare.com" in src) or (name and "cf" in name):
                                    target_iframe = iframe_el
                                    break
                            
                            if target_iframe:
                                box = await target_iframe.bounding_box()
                                if box:
                                    print("🖱️ Fallback: Clicking center of Turnstile iframe element...")
                                    cx = box['x'] + box['width'] / 2
                                    cy = box['y'] + box['height'] / 2
                                    await page.mouse.move(cx, cy, steps=10)
                                    await page.mouse.click(cx, cy)
                                else:
                                    print("⚠️ Turnstile iframe element found but has no bounding box.")
                            else:
                                print("⚠️ Could not match Turnstile frame to an iframe element on the main page.")
                        except Exception as e:
                            print(f"⚠️ Fallback click failed: {e}")

                else:
                    print("⚠️ Turnstile frame NOT found in page.frames list.")
                    # Last resort: Check if there is a 'Verify you are human' text and click near it?
                    pass
        
                # Now wait for challenge to complete
                current_title = await page.title()
                print(f"Waiting for challenge to complete. Current title: '{current_title}'")

                await page.wait_for_function(
                    "() => document.title.indexOf('Just a moment...') === -1", 
                    timeout=60000 # Increased timeout
                )
                print("✅ Cloudflare challenge passed.")
        
                await asyncio.sleep(4 + random.random())
            except Exception as e:
                print(f"❌ Cloudflare challenge took too long or failed: {e}")
                
                # Handle browser closed error
                if "closed" in str(e) or "Connection closed" in str(e):
                    print("♻️ Browser closed unexpectedly. Resetting global_browser...")
                    global_browser = None
                    global_page = None
                    # Optional: Retry immediately?
                    # await get_initial_data() 
                    return

                # Verbose error logging
                try:
                    error_title = await page.title()
                    error_url = page.url
                    # content = await page.content() # Content might be huge
                    text_content = await page.evaluate("document.body.innerText")
                    
                    print(f"🔍 Debug Info at Timeout:")
                    print(f"   - URL: {error_url}")
                    print(f"   - Title: {error_title}")
                    print(f"   - Page Text Preview: {text_content[:500].replace('\\n', ' ')}...")
                    
                    if "Access denied" in text_content:
                        print("   ⚠️ Detected 'Access denied' message.")
                    if "Challenge Validation failed" in text_content:
                        print("   ⚠️ Detected 'Challenge Validation failed' message.")
                        
                    # Check for iframes
                    frames = page.frames
                    print(f"   - Number of frames: {len(frames)}")
                    for i, frame in enumerate(frames):
                        try:
                            print(f"     Frame {i}: {frame.url}")
                        except:
                            pass
                            
                except Exception as debug_e:
                    print(f"   (Failed to capture debug info: {debug_e})")
                
                return

            await asyncio.sleep(5)

            # 3. Capture ALL cookies (including __cf_bm, etc.)
            cookies = await page.context.cookies()
            cookie_parts = []
            cf_clearance_found = False
            
            # Prioritize cf_clearance and __cf_bm
            for cookie in cookies:
                # Skip session-specific cookies that might conflict or expire quickly if not needed
                # But for now, let's keep everything to be safe, just formatting them correctly.
                cookie_parts.append(f"{cookie['name']}={cookie['value']}")
                if cookie['name'] == "cf_clearance":
                    cf_clearance_found = True
                if cookie['name'] == "__cf_bm":
                    print("✅ Found __cf_bm cookie")
            
            full_cookie_string = "; ".join(cookie_parts)
            
            config = get_config()
            # Save cookies even if cf_clearance is missing, as __cf_bm might be enough for some checks
            # or we might have passed the challenge but the cookie hasn't appeared yet (unlikely if we waited)
            if cookies:
                config["cf_clearance"] = next((c['value'] for c in cookies if c['name'] == "cf_clearance"), "")
                config["cookie_string"] = full_cookie_string
                config["user_agent"] = user_agent
                save_config(config)
                print(f"✅ Saved full cookie session ({len(cookies)} cookies)")
            else:
                print("⚠️ No cookies found to save.")

            # Extract models
            print("Extracting models from page...")
            try:
                body = await page.content()
                match = re.search(r'{\\"initialModels\\":(\[.*?\]),\\"initialModel[A-Z]Id', body, re.DOTALL)
                if match:
                    models_json = match.group(1).encode().decode('unicode_escape')
                    models = json.loads(models_json)
                    save_models(models)
                    print(f"✅ Saved {len(models)} models")
                else:
                    print("⚠️ Could not find models in page")
            except Exception as e:
                print(f"❌ Error extracting models: {e}")

            # --- NEW: Extract reCAPTCHA Token ---
            # Moved to refresh_recaptcha_token() called in api_chat_completions
            # ----------------------------------------

    except Exception as e:
        print(f"❌ An error occurred during initial data retrieval: {e}")
        # Check if the error is related to the browser being closed
        if "Target page, context or browser has been closed" in str(e) or "Connection closed" in str(e):
            print("⚠️ Browser connection lost. Resetting global browser instance.")
            global_browser = None
            global_page = None

async def periodic_refresh_task():
    """Background task to refresh cf_clearance and models every 2 minutes"""
    global active_generations
    while True:
        try:
            # Wait 2 minutes (120 seconds)
            await asyncio.sleep(120)
            
            # Check if there are active generations
            if active_generations > 0:
                print(f"⏳ Skipping scheduled refresh because there are {active_generations} active generations.")
                continue

            print("\n" + "="*60)
            print("🔄 Starting scheduled 2-minute refresh...")
            print("="*60)
            await get_initial_data()
            print("✅ Scheduled refresh completed")
            print("="*60 + "\n")
        except Exception as e:
            print(f"❌ Error in periodic refresh task: {e}")
            # Continue the loop even if there's an error
            continue

@app.on_event("startup")
async def startup_event():
    # Ensure config and models files exist
    save_config(get_config())
    save_models(get_models())
    # Load usage stats from config
    load_usage_stats()
    # Start initial data fetch
    asyncio.create_task(get_initial_data())
    # Start periodic refresh task (every 30 minutes)
    asyncio.create_task(periodic_refresh_task())

@app.on_event("shutdown")
async def shutdown_event():
    global global_browser
    if global_browser:
        print("🛑 Closing global browser instance...")
        try:
            await global_browser.__aexit__(None, None, None)
        except Exception as e:
            print(f"⚠️ Error closing browser (ignoring): {e}")
        global_browser = None

# --- UI Endpoints (Login/Dashboard) ---

@app.get("/", response_class=HTMLResponse)
async def root_redirect():
    return RedirectResponse(url="/dashboard")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    if await get_current_session(request):
        return RedirectResponse(url="/dashboard")
    
    error_msg = '<div class="error-message">Invalid password. Please try again.</div>' if error else ''
    
    return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - UMA !!!</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }}
                .login-container {{
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    width: 100%;
                    max-width: 400px;
                }}
                h1 {{
                    color: #333;
                    margin-bottom: 10px;
                    font-size: 28px;
                }}
                .subtitle {{
                    color: #666;
                    margin-bottom: 30px;
                    font-size: 14px;
                }}
                .form-group {{
                    margin-bottom: 20px;
                }}
                label {{
                    display: block;
                    margin-bottom: 8px;
                    color: #555;
                    font-weight: 500;
                }}
                input[type="password"] {{
                    width: 100%;
                    padding: 12px;
                    border: 2px solid #e1e8ed;
                    border-radius: 6px;
                    font-size: 16px;
                    transition: border-color 0.3s;
                }}
                input[type="password"]:focus {{
                    outline: none;
                    border-color: #667eea;
                }}
                button {{
                    width: 100%;
                    padding: 12px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    border-radius: 6px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: transform 0.2s;
                }}
                button:hover {{
                    transform: translateY(-2px);
                }}
                button:active {{
                    transform: translateY(0);
                }}
                .error-message {{
                    background: #fee;
                    color: #c33;
                    padding: 12px;
                    border-radius: 6px;
                    margin-bottom: 20px;
                    border-left: 4px solid #c33;
                }}
            </style>
        </head>
        <body>
            <div class="login-container">
                <h1>LMArena Bridge</h1>
                <div class="subtitle">Sign in to access the dashboard</div>
                {error_msg}
                <form action="/login" method="post">
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" placeholder="Enter your password" required autofocus>
                    </div>
                    <button type="submit">Sign In</button>
                </form>
            </div>
        </body>
        </html>
    """

@app.post("/login")
async def login_submit(response: Response, password: str = Form(...)):
    config = get_config()
    if password == config.get("password"):
        session_id = str(uuid.uuid4())
        dashboard_sessions[session_id] = "admin"
        response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="session_id", value=session_id, httponly=True)
        return response
    return RedirectResponse(url="/login?error=1", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/logout")
async def logout(request: Request, response: Response):
    session_id = request.cookies.get("session_id")
    if session_id in dashboard_sessions:
        del dashboard_sessions[session_id]
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("session_id")
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(session: str = Depends(get_current_session)):
    if not session:
        return RedirectResponse(url="/login")

    config = get_config()
    models = get_models()

    # Render API Keys
    keys_html = ""
    for key in config["api_keys"]:
        created_date = time.strftime('%Y-%m-%d %H:%M', time.localtime(key.get('created', 0)))
        keys_html += f"""
            <tr>
                <td><strong>{key['name']}</strong></td>
                <td><code class="api-key-code">{key['key']}</code></td>
                <td><span class="badge">{key.get('rpm', 60)} RPM</span></td>
                <td><span class="badge">{key.get('rpd', 'Unlimited')} RPD</span></td>
                <td><small>{created_date}</small></td>
                <td>
                    <form action='/delete-key' method='post' style='margin:0;' onsubmit='return confirm("Delete this API key?");'>
                        <input type='hidden' name='key_id' value='{key['key']}'>
                        <button type='submit' class='btn-delete'>Delete</button>
                    </form>
                </td>
            </tr>
        """

    # Render Auth Tokens
    auth_tokens = config.get("auth_tokens", [])
    tokens_html = ""
    if auth_tokens:
        for idx, token in enumerate(auth_tokens):
            token_preview = f"{token[:20]}...{token[-10:]}" if len(token) > 30 else token
            tokens_html += f"""
                <tr>
                    <td><strong>Token {idx + 1}</strong></td>
                    <td><code class="api-key-code">{token_preview}</code></td>
                    <td>
                        <form action='/delete-token' method='post' style='margin:0;' onsubmit='return confirm("Delete this auth token?");'>
                            <input type='hidden' name='token_index' value='{idx}'>
                            <button type='submit' class='btn-delete'>Delete</button>
                        </form>
                    </td>
                </tr>
            """
    else:
        tokens_html = '<tr><td colspan="3" class="no-data">No auth tokens configured</td></tr>'

    # Render Models (limit to first 20 with text output)
    text_models = [m for m in models if m.get('capabilities', {}).get('outputCapabilities', {}).get('text')]
    models_html = ""
    for i, model in enumerate(text_models[:20]):
        rank = model.get('rank', '?')
        org = model.get('organization', 'Unknown')
        models_html += f"""
            <div class="model-card">
                <div class="model-header">
                    <span class="model-name">{model.get('publicName', 'Unnamed')}</span>
                    <span class="model-rank">Rank {rank}</span>
                </div>
                <div class="model-org">{org}</div>
            </div>
        """
    
    if not models_html:
        models_html = '<div class="no-data">No models found. Token may be invalid or expired.</div>'

    # Render Stats
    stats_html = ""
    if model_usage_stats:
        for model, count in sorted(model_usage_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            stats_html += f"<tr><td>{model}</td><td><strong>{count}</strong></td></tr>"
    else:
        stats_html = "<tr><td colspan='2' class='no-data'>No usage data yet</td></tr>"

    # Check token status
    token_status = "✅ Configured" if config.get("auth_token") else "❌ Not Set"
    token_class = "status-good" if config.get("auth_token") else "status-bad"
    
    cf_status = "✅ Configured" if config.get("cf_clearance") else "❌ Not Set"
    cf_class = "status-good" if config.get("cf_clearance") else "status-bad"
    
    # Get recent activity count (last 24 hours)
    recent_activity = sum(1 for timestamps in api_key_usage.values() for t in timestamps if time.time() - t < 86400)

    return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - LMArena Bridge</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>
            <style>
                @keyframes fadeIn {{
                    from {{ opacity: 0; transform: translateY(20px); }}
                    to {{ opacity: 1; transform: translateY(0); }}
                }}
                @keyframes slideIn {{
                    from {{ opacity: 0; transform: translateX(-20px); }}
                    to {{ opacity: 1; transform: translateX(0); }}
                }}
                @keyframes pulse {{
                    0%, 100% {{ transform: scale(1); }}
                    50% {{ transform: scale(1.05); }}
                }}
                @keyframes shimmer {{
                    0% {{ background-position: -1000px 0; }}
                    100% {{ background-position: 1000px 0; }}
                }}
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    background: #f5f7fa;
                    color: #333;
                    line-height: 1.6;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px 0;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .header-content {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 0 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                h1 {{
                    font-size: 24px;
                    font-weight: 600;
                }}
                .logout-btn {{
                    background: rgba(255,255,255,0.2);
                    color: white;
                    padding: 8px 16px;
                    border-radius: 6px;
                    text-decoration: none;
                    transition: background 0.3s;
                }}
                .logout-btn:hover {{
                    background: rgba(255,255,255,0.3);
                }}
                .container {{
                    max-width: 1200px;
                    margin: 30px auto;
                    padding: 0 20px;
                }}
                .section {{
                    background: white;
                    border-radius: 10px;
                    padding: 25px;
                    margin-bottom: 25px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
                }}
                .section-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 20px;
                    padding-bottom: 15px;
                    border-bottom: 2px solid #f0f0f0;
                }}
                h2 {{
                    font-size: 20px;
                    color: #333;
                    font-weight: 600;
                }}
                .status-badge {{
                    padding: 6px 12px;
                    border-radius: 6px;
                    font-size: 13px;
                    font-weight: 600;
                }}
                .status-good {{ background: #d4edda; color: #155724; }}
                .status-bad {{ background: #f8d7da; color: #721c24; }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                th {{
                    background: #f8f9fa;
                    padding: 12px;
                    text-align: left;
                    font-weight: 600;
                    color: #555;
                    font-size: 14px;
                    border-bottom: 2px solid #e9ecef;
                }}
                td {{
                    padding: 12px;
                    border-bottom: 1px solid #f0f0f0;
                }}
                tr:hover {{
                    background: #f8f9fa;
                }}
                .form-group {{
                    margin-bottom: 15px;
                }}
                label {{
                    display: block;
                    margin-bottom: 6px;
                    font-weight: 500;
                    color: #555;
                }}
                input[type="text"], input[type="number"], textarea {{
                    width: 100%;
                    padding: 10px;
                    border: 2px solid #e1e8ed;
                    border-radius: 6px;
                    font-size: 14px;
                    font-family: inherit;
                    transition: border-color 0.3s;
                }}
                input:focus, textarea:focus {{
                    outline: none;
                    border-color: #667eea;
                }}
                textarea {{
                    resize: vertical;
                    font-family: 'Courier New', monospace;
                    min-height: 100px;
                }}
                button, .btn {{
                    padding: 10px 20px;
                    border: none;
                    border-radius: 6px;
                    font-size: 14px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s;
                }}
                button[type="submit"]:not(.btn-delete) {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                }}
                button[type="submit"]:not(.btn-delete):hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
                }}
                .btn-delete {{
                    background: #dc3545;
                    color: white;
                    padding: 6px 12px;
                    font-size: 13px;
                }}
                .btn-delete:hover {{
                    background: #c82333;
                }}
                .api-key-code {{
                    background: #f8f9fa;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-family: 'Courier New', monospace;
                    font-size: 12px;
                    color: #495057;
                }}
                .badge {{
                    background: #e7f3ff;
                    color: #0066cc;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: 600;
                }}
                .model-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                    gap: 15px;
                    margin-top: 15px;
                }}
                .model-card {{
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 8px;
                    border-left: 4px solid #667eea;
                }}
                .model-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 8px;
                }}
                .model-name {{
                    font-weight: 600;
                    color: #333;
                    font-size: 14px;
                }}
                .model-rank {{
                    background: #667eea;
                    color: white;
                    padding: 2px 8px;
                    border-radius: 12px;
                    font-size: 11px;
                    font-weight: 600;
                }}
                .model-org {{
                    color: #666;
                    font-size: 12px;
                }}
                .no-data {{
                    text-align: center;
                    color: #999;
                    padding: 20px;
                    font-style: italic;
                }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 20px;
                }}
                .stat-card {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                    animation: fadeIn 0.6s ease-out;
                    transition: transform 0.3s;
                }}
                .stat-card:hover {{
                    transform: translateY(-5px);
                    box-shadow: 0 8px 16px rgba(102, 126, 234, 0.4);
                }}
                .section {{
                    animation: slideIn 0.5s ease-out;
                }}
                .section:nth-child(2) {{ animation-delay: 0.1s; }}
                .section:nth-child(3) {{ animation-delay: 0.2s; }}
                .section:nth-child(4) {{ animation-delay: 0.3s; }}
                .model-card {{
                    animation: fadeIn 0.4s ease-out;
                    transition: transform 0.2s, box-shadow 0.2s;
                }}
                .model-card:hover {{
                    transform: translateY(-3px);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                }}
                .stat-value {{
                    font-size: 32px;
                    font-weight: bold;
                    margin-bottom: 5px;
                }}
                .stat-label {{
                    font-size: 14px;
                    opacity: 0.9;
                }}
                .form-row {{
                    display: grid;
                    grid-template-columns: 2fr 1fr auto;
                    gap: 10px;
                    align-items: end;
                }}
                @media (max-width: 768px) {{
                    .form-row {{
                        grid-template-columns: 1fr;
                    }}
                    .model-grid {{
                        grid-template-columns: 1fr;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <div class="header-content">
                    <h1>🚀 LMArena Bridge Dashboard</h1>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>

            <div class="container">
                <!-- Stats Overview -->
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{len(config['api_keys'])}</div>
                        <div class="stat-label">API Keys</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{len(text_models)}</div>
                        <div class="stat-label">Available Models</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{sum(model_usage_stats.values())}</div>
                        <div class="stat-label">Total Requests</div>
                    </div>
                </div>

                <!-- Arena Auth Token -->
                <div class="section">
                    <div class="section-header">
                        <h2>🔐 Arena Authentication</h2>
                        <span class="status-badge {token_class}">{len(auth_tokens)} Token(s)</span>
                    </div>
                    
                    <table style="margin-bottom: 20px;">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Token</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {tokens_html}
                        </tbody>
                    </table>
                    
                    <h3 style="margin-top: 30px; margin-bottom: 15px; font-size: 18px;">Add New Tokens</h3>
                    <form action="/update-auth-tokens" method="post">
                        <div class="form-group">
                            <label for="auth_tokens">Arena Auth Tokens (one per line)</label>
                            <textarea id="auth_tokens" name="auth_tokens" placeholder="Paste your arena-auth-prod-v1 tokens here (one per line)" rows="8"></textarea>
                            <small>Add multiple tokens to distribute requests and avoid rate limits</small>
                        </div>
                        <button type="submit">Add Tokens</button>
                    </form>
                </div>

                <!-- Cloudflare Clearance -->
                <div class="section">
                    <div class="section-header">
                        <h2>☁️ Cloudflare Clearance</h2>
                        <span class="status-badge {cf_class}">{cf_status}</span>
                    </div>
                    <p style="color: #666; margin-bottom: 15px;">This is automatically fetched on startup. If API requests fail with 404 errors, the token may have expired.</p>
                    <code style="background: #f8f9fa; padding: 10px; display: block; border-radius: 6px; word-break: break-all; margin-bottom: 15px;">
                        {config.get("cf_clearance", "Not set")}
                    </code>
                    <form action="/refresh-tokens" method="post" style="margin-top: 15px;">
                        <button type="submit" style="background: #28a745;">🔄 Refresh Tokens &amp; Models</button>
                    </form>
                    <p style="color: #999; font-size: 13px; margin-top: 10px;"><em>Note: This will fetch a fresh cf_clearance token and update the model list.</em></p>
                </div>

                <!-- API Keys -->
                <div class="section">
                    <div class="section-header">
                        <h2>🔑 API Keys</h2>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Key</th>
                                <th>Rate Limit (RPM)</th>
                                <th>Daily Limit (RPD)</th>
                                <th>Created</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {keys_html if keys_html else '<tr><td colspan="6" class="no-data">No API keys configured</td></tr>'}
                        </tbody>
                    </table>
                    
                    <h3 style="margin-top: 30px; margin-bottom: 15px; font-size: 18px;">Create New API Key</h3>
                    <form action="/create-key" method="post">
                        <div class="form-row">
                            <div class="form-group">
                                <label for="name">Key Name</label>
                                <input type="text" id="name" name="name" placeholder="e.g., Production Key" required>
                            </div>
                            <div class="form-group">
                                <label for="rpm">Rate Limit (RPM)</label>
                                <input type="number" id="rpm" name="rpm" value="60" min="1" max="1000" required>
                            </div>
                            <div class="form-group">
                                <label for="rpd">Daily Limit (RPD)</label>
                                <input type="number" id="rpd" name="rpd" value="10000" min="1" required>
                            </div>
                            <div class="form-group">
                                <label>&nbsp;</label>
                                <button type="submit">Create Key</button>
                            </div>
                        </div>
                    </form>
                </div>

                <!-- Usage Statistics -->
                <div class="section">
                    <div class="section-header">
                        <h2>📊 Usage Statistics</h2>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 30px;">
                        <div>
                            <h3 style="text-align: center; margin-bottom: 15px; font-size: 16px; color: #666;">Model Usage Distribution</h3>
                            <canvas id="modelPieChart" style="max-height: 300px;"></canvas>
                        </div>
                        <div>
                            <h3 style="text-align: center; margin-bottom: 15px; font-size: 16px; color: #666;">Request Count by Model</h3>
                            <canvas id="modelBarChart" style="max-height: 300px;"></canvas>
                        </div>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Model</th>
                                <th>Requests</th>
                            </tr>
                        </thead>
                        <tbody>
                            {stats_html}
                        </tbody>
                    </table>
                </div>

                <!-- Available Models -->
                <div class="section">
                    <div class="section-header">
                        <h2>🤖 Available Models</h2>
                    </div>
                    <p style="color: #666; margin-bottom: 15px;">Showing top 20 text-based models (Rank 1 = Best)</p>
                    <div class="model-grid">
                        {models_html}
                    </div>
                </div>
            </div>
            
            <script>
                // Prepare data for charts
                const statsData = {json.dumps(dict(sorted(model_usage_stats.items(), key=lambda x: x[1], reverse=True)[:10]))};
                const modelNames = Object.keys(statsData);
                const modelCounts = Object.values(statsData);
                
                // Generate colors for charts
                const colors = [
                    '#667eea', '#764ba2', '#f093fb', '#4facfe',
                    '#43e97b', '#fa709a', '#fee140', '#30cfd0',
                    '#a8edea', '#fed6e3'
                ];
                
                // Pie Chart
                if (modelNames.length > 0) {{
                    const pieCtx = document.getElementById('modelPieChart').getContext('2d');
                    new Chart(pieCtx, {{
                        type: 'doughnut',
                        data: {{
                            labels: modelNames,
                            datasets: [{{
                                data: modelCounts,
                                backgroundColor: colors,
                                borderWidth: 2,
                                borderColor: '#fff'
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: true,
                            plugins: {{
                                legend: {{
                                    position: 'bottom',
                                    labels: {{
                                        padding: 15,
                                        font: {{
                                            size: 11
                                        }}
                                    }}
                                }},
                                tooltip: {{
                                    callbacks: {{
                                        label: function(context) {{
                                            const label = context.label || '';
                                            const value = context.parsed || 0;
                                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                            const percentage = ((value / total) * 100).toFixed(1);
                                            return label + ': ' + value + ' (' + percentage + '%)';
                                        }}
                                    }}
                                }}
                            }}
                        }}
                    }});
                    
                    // Bar Chart
                    const barCtx = document.getElementById('modelBarChart').getContext('2d');
                    new Chart(barCtx, {{
                        type: 'bar',
                        data: {{
                            labels: modelNames,
                            datasets: [{{
                                label: 'Requests',
                                data: modelCounts,
                                backgroundColor: colors[0],
                                borderColor: colors[1],
                                borderWidth: 1
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: true,
                            plugins: {{
                                legend: {{
                                    display: false
                                }},
                                tooltip: {{
                                    callbacks: {{
                                        label: function(context) {{
                                            return 'Requests: ' + context.parsed.y;
                                        }}
                                    }}
                                }}
                            }},
                            scales: {{
                                y: {{
                                    beginAtZero: true,
                                    ticks: {{
                                        stepSize: 1
                                    }}
                                }},
                                x: {{
                                    ticks: {{
                                        font: {{
                                            size: 10
                                        }},
                                        maxRotation: 45,
                                        minRotation: 45
                                    }}
                                }}
                            }}
                        }}
                    }});
                }} else {{
                    // Show "no data" message
                    document.getElementById('modelPieChart').parentElement.innerHTML = '<p style="text-align: center; color: #999; padding: 50px;">No usage data yet</p>';
                    document.getElementById('modelBarChart').parentElement.innerHTML = '<p style="text-align: center; color: #999; padding: 50px;">No usage data yet</p>';
                }}
            </script>
        </body>
        </html>
    """

@app.post("/update-auth-tokens")
async def update_auth_tokens(request: Request, auth_tokens: str = Form(...)):
    session = await get_current_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=303)
    
    config = get_config()
    
    # Split by newlines and filter out empty lines
    new_tokens = [t.strip() for t in auth_tokens.split('\n') if t.strip()]
    
    # Append new tokens to existing ones (avoid duplicates)
    existing_tokens = config.get("auth_tokens", [])
    for token in new_tokens:
        if token not in existing_tokens:
            existing_tokens.append(token)
    
    config["auth_tokens"] = existing_tokens
    save_config(config)
    
    return RedirectResponse(url="/dashboard?success=tokens_updated", status_code=303)

@app.post("/delete-token")
async def delete_token(session: str = Depends(get_current_session), token_index: int = Form(...)):
    if not session:
        return RedirectResponse(url="/login")
    config = get_config()
    auth_tokens = config.get("auth_tokens", [])
    
    # Validate index
    if 0 <= token_index < len(auth_tokens):
        deleted_token = auth_tokens.pop(token_index)
        config["auth_tokens"] = auth_tokens
        save_config(config)
        debug_print(f"🗑️ Deleted auth token at index {token_index}: {deleted_token[:20]}...")
    
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/create-key")
async def create_key(session: str = Depends(get_current_session), name: str = Form(...), rpm: int = Form(...), rpd: int = Form(...)):
    if not session:
        return RedirectResponse(url="/login")
    config = get_config()
    new_key = {
        "name": name.strip(),
        "key": f"sk-lmab-{uuid.uuid4()}",
        "rpm": max(1, min(rpm, 1000)),  # Clamp between 1-1000
        "rpd": max(1, rpd),             # Minimum 1
        "created": int(time.time())
    }
    config["api_keys"].append(new_key)
    save_config(config)
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/delete-key")
async def delete_key(session: str = Depends(get_current_session), key_id: str = Form(...)):
    if not session:
        return RedirectResponse(url="/login")
    config = get_config()
    config["api_keys"] = [k for k in config["api_keys"] if k["key"] != key_id]
    save_config(config)
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/refresh-tokens")
async def refresh_tokens(session: str = Depends(get_current_session)):
    if not session:
        return RedirectResponse(url="/login")
    await get_initial_data()
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

# --- OpenAI Compatible API Endpoints ---

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint for monitoring"""
    try:
        models = get_models()
        config = get_config()
        
        # Basic health checks
        has_cf_clearance = bool(config.get("cf_clearance"))
        has_models = len(models) > 0
        has_api_keys = len(config.get("api_keys", [])) > 0
        
        status = "healthy" if (has_cf_clearance and has_models) else "degraded"
        
        return {
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {
                "cf_clearance": has_cf_clearance,
                "models_loaded": has_models,
                "model_count": len(models),
                "api_keys_configured": has_api_keys
            }
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e)
        }

@app.get("/v1/models")
async def list_models():
    """Lists available models from a text file in an OpenAI-compatible format."""
    
    # Read allowed models from a text file
    allowed_models = []
    try:
        with open("allowed_models.txt", "r") as f:
            allowed_models = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        # If file doesn't exist, return empty list
        allowed_models = []
    
    # Build model list from allowed models
    filtered_models = []
    for model_name in allowed_models:
        filtered_models.append({
            "id": model_name,
            "object": "model",
            "created": int(asyncio.get_event_loop().time()),
            "owned_by": "vvv",
            "type": "chat"  # Default type since we only have model names
        })
    
    return {
        "object": "list",
        "data": filtered_models
    }

async def refresh_recaptcha_token():
    global global_page
    page = global_page
    if not page:
        print("❌ No active page found for reCAPTCHA generation")
        return None
        
    print("🕵️ Attempting to extract reCAPTCHA token...")
    try:
        # We need to find the site key first. It's usually in the HTML.
        # Look for 'grecaptcha.execute("SITE_KEY"' or similar
        # Or just try to execute grecaptcha if it's loaded
        
        # 1. Check if grecaptcha is defined (wait for it) - OPTIMIZED: Reduced wait time
        is_grecaptcha = False
        print("   Waiting for grecaptcha to load...")
        for i in range(10):  # Reduced from 20 to 10 seconds
            is_grecaptcha = await page.evaluate("typeof grecaptcha !== 'undefined' || typeof window.grecaptcha !== 'undefined'")
            if is_grecaptcha:
                break
            await asyncio.sleep(0.5)  # Reduced from 1s to 0.5s
        
        if is_grecaptcha:
            print("✅ grecaptcha is defined on the page.")
            
            # 2. Try to execute it with a common action
            # We need the site key. Sometimes it's not needed if we use the 'execute' method on the object directly if it's already initialized?
            # No, usually grecaptcha.execute('KEY', ...)
            
            # Let's try to find the key in the page content
            content = await page.content()
            # Common patterns for site key
            # "sitekey": "..."
            # grecaptcha.execute("..."
            
            site_key_match = re.search(r'grecaptcha\.execute\("([^"]+)"', content)
            if not site_key_match:
                site_key_match = re.search(r'sitekey["\']?: ?["\']([^"\']+)["\']', content)
            
            site_key = None
            if site_key_match:
                site_key = site_key_match.group(1)
                print(f"✅ Found reCAPTCHA site key via regex: {site_key}")

            # Fallback: Look for the script tag with render=KEY
            if not site_key:
                script_src = await page.evaluate("""
                    () => {
                        const scripts = Array.from(document.querySelectorAll('script[src*="recaptcha"]'));
                        return scripts.map(s => s.src).find(s => s.includes('render='));
                    }
                """)
                if script_src:
                    import urllib.parse
                    parsed = urllib.parse.urlparse(script_src)
                    qs = urllib.parse.parse_qs(parsed.query)
                    if 'render' in qs:
                        site_key = qs['render'][0]
                        print(f"✅ Found site key from script src: {site_key}")

            if site_key:
                # Execute reCAPTCHA
                # We might need to wait for it to be ready
                print(f"   Executing reCAPTCHA with key: {site_key}")
                token = await page.evaluate(f"""
                    new Promise((resolve, reject) => {{
                        const g = window.grecaptcha || grecaptcha;
                        g.ready(() => {{
                            g.execute('{site_key}', {{action: 'submit'}})
                                .then(resolve)
                                .catch(err => {{
                                    console.error("reCAPTCHA execution error:", err);
                                    resolve(null);
                                }});
                        }});
                    }})
                """)
                
                if token:
                    print(f"✅ Generated reCAPTCHA token: {token[:20]}...")
                    config = get_config()
                    config["recaptcha_token"] = token
                    config["recaptcha_last_refresh"] = time.time()
                    save_config(config)
                    return token
                else:
                    print("⚠️ reCAPTCHA execution returned null/empty token.")
            else:
                print("⚠️ Could not find reCAPTCHA site key in page source.")
        else:
            print("⚠️ grecaptcha is NOT defined on the page (timed out).")
            
            # Try to inject script manually if we found the key in logs previously
            # Key: 6Led_uYrAAAAAKjxDIF58fgFtX3t8loNAK85bW9I
            print("   Attempting to extract token via DOM bridge (checking page context)...")
            try:
                # Debug: Print all script tags and their nonces
                print("   Scanning for existing scripts and nonces...")
                scripts_info = await page.evaluate("""
                    () => {
                        return Array.from(document.scripts).map(s => ({
                            src: s.src,
                            nonce: s.nonce,
                            type: s.type
                        }));
                    }
                """)
                found_nonce = None
                for s in scripts_info:
                    if s['nonce']:
                        print(f"   Found nonce: {s['nonce']} on script {s['src'][:50]}...")
                        found_nonce = s['nonce']
                        break
                
                if not found_nonce:
                    print("   ⚠️ No nonce found on existing scripts.")

                # 1. Create a hidden input for the token
                await page.evaluate("""
                    () => {
                        if (!document.getElementById('recaptcha-token-output')) {
                            const input = document.createElement('input');
                            input.id = 'recaptcha-token-output';
                            input.type = 'hidden';
                            document.body.appendChild(input);
                            console.log("Created hidden input for token");
                        }
                    }
                """)

                # 2. Inject the reCAPTCHA library script FIRST (with nonce if found)
                print("   Injecting reCAPTCHA library...")
                await page.evaluate(f"""
                    () => {{
                        const script = document.createElement('script');
                        script.src = "https://www.google.com/recaptcha/enterprise.js?render=6Led_uYrAAAAAKjxDIF58fgFtX3t8loNAK85bW9I";
                        script.async = true;
                        script.defer = true;
                        if ("{found_nonce or ''}") {{
                            script.nonce = "{found_nonce or ''}";
                        }}
                        document.head.appendChild(script);
                        console.log("Injected reCAPTCHA library script");
                    }}
                """)

                # 3. Inject a checker script that runs in the PAGE context
                # We use the same nonce for this inline script too
                print("   Injecting checker script...")
                await page.evaluate(f"""
                    () => {{
                        const script = document.createElement('script');
                        if ("{found_nonce or ''}") {{
                            script.nonce = "{found_nonce or ''}";
                        }}
                        script.textContent = `
                            console.log("Token extractor started in page context");
                            
                            const checkAndExecute = setInterval(() => {{
                                const g = window.grecaptcha;
                                if (g) {{
                                    console.log("grecaptcha found!", g);
                                    clearInterval(checkAndExecute);
                                    
                                    const execute = () => {{
                                        const enterprise = g.enterprise || g;
                                        enterprise.ready(() => {{
                                            console.log("grecaptcha ready, executing...");
                                            enterprise.execute('6Led_uYrAAAAAKjxDIF58fgFtX3t8loNAK85bW9I', {{action: 'submit'}})
                                                .then(token => {{
                                                    console.log("Token generated!");
                                                    document.getElementById('recaptcha-token-output').value = token;
                                                }})
                                                .catch(err => {{
                                                    console.error("Execution error:", err);
                                                    document.getElementById('recaptcha-token-output').value = "ERROR: " + err.toString();
                                                }});
                                        }});
                                    }};
                                    
                                    execute();
                                }}
                            }}, 1000);
                            
                            // Stop after 60 seconds
                            setTimeout(() => clearInterval(checkAndExecute), 60000);
                        `;
                        document.body.appendChild(script);
                    }}
                """)
                
                # 4. Wait for the token to appear in the input - OPTIMIZED
                print("   Waiting for token in hidden input...")
                token = None
                for _ in range(30):  # Reduced from 60 to 30 seconds
                    token = await page.evaluate("document.getElementById('recaptcha-token-output').value")
                    if token:
                        break
                    await asyncio.sleep(0.5)  # Reduced from 1s to 0.5s
                
                if token and not token.startswith("ERROR"):
                    print(f"✅ Generated reCAPTCHA token via DOM bridge: {token[:20]}...")
                    config = get_config()
                    config["recaptcha_token"] = token
                    config["recaptcha_last_refresh"] = time.time()
                    save_config(config)
                    return token
                else:
                    print(f"❌ Token generation failed (DOM bridge): {token}")
                    
            except Exception as e:
                print(f"   ❌ Injection failed: {e}")
                # Debug: print all script srcs
                scripts = await page.evaluate("Array.from(document.scripts).map(s => s.src)")
                print(f"   Scripts loaded: {[s for s in scripts if 'recaptcha' in s or 'google' in s]}")
    except Exception as e:
        print(f"⚠️ Error extracting reCAPTCHA token: {e}")
    
    return None

@app.post("/v1/chat/completions")
async def api_chat_completions(request: Request, api_key: dict = Depends(rate_limit_api_key)):
    global active_generations
    active_generations += 1
    should_decrement = True
    try:
        # OPTIMIZATION: Only refresh token if not recently generated or missing
        config = get_config()
        recaptcha_token = config.get("recaptcha_token")
        last_refresh = config.get("recaptcha_last_refresh", 0)
        current_time = time.time()
        
        # Refresh only if token is missing or older than 60 seconds
        if not recaptcha_token or (current_time - last_refresh) > 60:
            debug_print("🔄 Generating fresh reCAPTCHA token...")
            await refresh_recaptcha_token()
            config = get_config()
            config["recaptcha_last_refresh"] = current_time
            save_config(config)
        else:
            debug_print(f"♻️ Reusing cached reCAPTCHA token (age: {int(current_time - last_refresh)}s)")

        debug_print("\n" + "="*80)
        debug_print("🔵 NEW API REQUEST RECEIVED")
        debug_print("="*80)
        
        # Parse request body with error handling
        try:
            body = await request.json()
        except json.JSONDecodeError as e:
            debug_print(f"❌ Invalid JSON in request body: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON in request body.")
        except Exception as e:
            debug_print(f"❌ Failed to read request body: {e}")
            raise HTTPException(status_code=400, detail="Failed to read request body.")
        
        debug_print(f"📥 Request body keys: {list(body.keys())}")
        
        # Validate required fields
        model_public_name = body.get("model")
        messages = body.get("messages", [])
        stream = body.get("stream", False)
        
        debug_print(f"🌊 Stream mode: {stream}")
        debug_print(f"🤖 Requested model: {model_public_name}")
        debug_print(f"💬 Number of messages: {len(messages)}")
        
        if not model_public_name:
            debug_print("❌ Missing 'model' in request")
            raise HTTPException(status_code=400, detail="Missing 'model' in request body.")
        
        if not messages:
            debug_print("❌ Missing 'messages' in request")
            raise HTTPException(status_code=400, detail="Missing 'messages' in request body.")
        
        if not isinstance(messages, list):
            debug_print("❌ 'messages' must be an array")
            raise HTTPException(status_code=400, detail="'messages' must be an array.")
        
        if len(messages) == 0:
            debug_print("❌ 'messages' array is empty")
            raise HTTPException(status_code=400, detail="'messages' array cannot be empty.")

        # Find model ID from public name
        try:
            models = get_models()
            debug_print(f"📚 Total models loaded: {len(models)}")
        except Exception as e:
            debug_print(f"❌ Failed to load models: {e}")
            raise HTTPException(
                status_code=503,
                detail="Failed to load model list from LMArena. Please try again later."
            )
        
        model_id = None
        model_org = None
        model_capabilities = {}
        
        for m in models:
            if m.get("publicName") == model_public_name:
                model_id = m.get("id")
                model_org = m.get("organization")
                model_capabilities = m.get("capabilities", {})
                break
        
        if not model_id:
            debug_print(f"❌ Model '{model_public_name}' not found in model list")
            raise HTTPException(
                status_code=404, 
                detail=f"Model '{model_public_name}' not found. Use /api/v1/models to see available models."
            )
        
        # Check if model is a stealth model (no organization)
        if not model_org:
            debug_print(f"❌ Model '{model_public_name}' is a stealth model (no organization)")
            raise HTTPException(
                status_code=403,
                detail="You do not have access to stealth models. Contact cloudwaddie for more info."
            )
        
        debug_print(f"✅ Found model ID: {model_id}")
        debug_print(f"🔧 Model capabilities: {model_capabilities}")

        # Log usage
        try:
            model_usage_stats[model_public_name] += 1
            # Save stats immediately after incrementing
            config = get_config()
            config["usage_stats"] = dict(model_usage_stats)
            save_config(config)
        except Exception as e:
            # Don't fail the request if usage logging fails
            debug_print(f"⚠️  Failed to log usage stats: {e}")

        # Build conversation history including system, user, and assistant messages
        conversation_history = []
        system_prompt = ""


        # Extract system messages first
        system_messages = [m for m in messages if m.get("role") == "system"]
        if system_messages:
            system_prompt = "\n\n".join([m.get("content", "") for m in system_messages])
            debug_print(f"📋 System prompt found: {system_prompt[:100]}..." if len(system_prompt) > 100 else f"📋 System prompt: {system_prompt}")

        # Build conversation history from user and assistant messages (excluding the last one)
        # We exclude the last one because it will be processed as the 'prompt' below
        for msg in messages[:-1]:
            role = msg.get("role")
            content = msg.get("content", "")
    
            if role == "user":
                conversation_history.append(f"User: {content}")
            elif role == "assistant":
                conversation_history.append(f"Char: {content}")

        debug_print(f"💬 Conversation history entries: {len(conversation_history)}")

        # Process last message content (may include images)
        try:
            last_message_content = messages[-1].get("content", "")
            prompt, experimental_attachments = await process_message_content(last_message_content, model_capabilities)
    
            # Build final prompt: System + History + Current prompt
            final_prompt_parts = []
    
            if system_prompt:
                final_prompt_parts.append(system_prompt)
    
            # Add conversation history
            if conversation_history:
                final_prompt_parts.append("\n\n".join(conversation_history))
    
            # Add current user message
            final_prompt_parts.append(f"User: {prompt}")
    
            prompt = "\n\n".join(final_prompt_parts)
            debug_print(f"✅ Built conversation with {len(conversation_history)} history entries")
    
        except Exception as e:
            debug_print(f"❌ Failed to process message content: {e}")
            raise HTTPException(
                status_code=400,
                detail=f"Failed to process message content."
            )
        
        # Validate prompt
        if not prompt:
            # If no text but has attachments, that's okay for vision models
            if not experimental_attachments:
                debug_print("❌ Last message has no content")
                raise HTTPException(status_code=400, detail="Last message must have content.")
        
        # Log prompt length for debugging character limit issues
        debug_print(f"📝 User prompt length: {len(prompt)} characters")
        debug_print(f"🖼️  Attachments: {len(experimental_attachments)} images")
        debug_print(f"📝 User prompt preview: {prompt[:100]}..." if len(prompt) > 100 else f"📝 User prompt: {prompt}")
        
        # Check for reasonable character limit (LMArena appears to have limits)
        # Typical limit seems to be around 32K-64K characters based on testing (DISABLED FOR NOW)
        #MAX_PROMPT_LENGTH = 200000  # Conservative estimate
        #if len(prompt) > MAX_PROMPT_LENGTH:
        #    error_msg = f"Limit or lower your context size under 35k broski."
        #    debug_print(f"❌ {error_msg}")
        #    raise HTTPException(status_code=400, detail=error_msg)
        
        # Use API key + conversation tracking
        api_key_str = api_key["key"]
        
        # Generate unique conversation ID for each request (no session continuation)
        import hashlib
        conversation_key = f"{api_key_str}_{model_public_name}_{time.time()}_{uuid.uuid4()}"
        conversation_id = hashlib.sha256(conversation_key.encode()).hexdigest()[:16]
        
        debug_print(f"🔑 API Key: {api_key_str[:20]}...")
        debug_print(f"💭 Auto-generated Conversation ID: {conversation_id}")
        debug_print(f"🔑 Conversation key: {conversation_key[:100]}...")
        
        debug_print("🆕 Creating NEW conversation session")
        # New conversation - Generate session ID once
        # Note: This session_id is used as the "evaluationSessionId" for messages,
        # but the root "id" of the payload must be unique for every request.
        
        # Chunking Logic
        chunks = []
        if len(prompt) > CHUNK_SIZE:
            debug_print(f"✂️ Prompt length {len(prompt)} > {CHUNK_SIZE}. Splitting into chunks...")
            for i in range(0, len(prompt), CHUNK_SIZE):
                chunks.append(prompt[i:i+CHUNK_SIZE])
            debug_print(f"🧩 Split into {len(chunks)} chunks")
        else:
            chunks.append(prompt)
            
        total_chunks = len(chunks)
        url = "https://lmarena.ai/nextjs-api/stream/create-evaluation"
        
        # Local history for this multi-turn request
        local_messages = []

        async def get_chunk_payload(chunk_index, chunk_content, is_last, session_id, is_new_session):
            # Prepare content with warnings if needed
            final_content = chunk_content
            if total_chunks > 1:
                current_chunk_num = chunk_index + 1
                if not is_last:
                    final_content += f"\n\n[THIS IS ONLY THE {current_chunk_num} OF {total_chunks} TOTAL CHUNKS. GIVEN THAT THE CHUNKS ARE NOT YET COMPLETE, SAVE THIS TO YOUR MEMORY FOR THE MEANTIME AND ONLY RESPOND WITH A DOT.]"
                else:
                    final_content = f"[YOU CAN RESPOND NOW. THIS IS THE CHUNK {current_chunk_num} OF {total_chunks}]\n\n" + final_content

            # Generate IDs for this turn
            payload_id = str(uuid7())
            user_msg_id = str(uuid7())
            model_msg_id = str(uuid7())
            
            # Determine parent ID
            parent_ids = []
            if local_messages:
                parent_ids = [local_messages[-1]["id"]]
            
            # Prepare User Message Object (for history later)
            user_msg_obj = {
                "id": user_msg_id,
                "role": "user",
                "content": final_content,
                "experimental_attachments": experimental_attachments if is_last else [],
                "parentMessageIds": parent_ids,
                "participantPosition": "a",
                "modelId": None,
                "evaluationSessionId": session_id,
                "status": "pending",
                "failureReason": None
            }
            
            # Prepare Model Message Object (for history later)
            model_msg_obj = {
                "id": model_msg_id,
                "role": "assistant",
                "content": "", # Will be filled by response
                "experimental_attachments": [],
                "parentMessageIds": [user_msg_id],
                "participantPosition": "a",
                "modelId": model_id,
                "evaluationSessionId": session_id,
                "status": "pending",
                "failureReason": None
            }
            
            # Construct payload
            # We use 'userMessage' for the current message, and 'messages' for history.
            
            payload_messages = []
            
            # LOGIC UPDATE: Send history if it's the first chunk OR if we just rotated sessions
            if is_new_session:
                for msg in local_messages:
                    msg_copy = msg.copy()
                    msg_copy["evaluationSessionId"] = session_id # Import history into NEW session
                    payload_messages.append(msg_copy)
            
            payload = {
                "id": payload_id,
                "mode": "direct",
                "modelAId": model_id,
                "userMessageId": user_msg_id,
                "modelAMessageId": model_msg_id,
                "userMessage": {
                    "content": final_content,
                    "experimental_attachments": experimental_attachments if is_last else [],
                },
                "modality": "chat",
                "recaptchaV3Token": "03AFcWeA..." # Placeholder, will be replaced if we have a real token
            }
            
            # Try to inject a real reCAPTCHA token if available in config
            config = get_config()
            if config.get("recaptcha_token"):
                 payload["recaptchaV3Token"] = config.get("recaptcha_token")
            
            # Only add 'messages' if we have history
            if payload_messages:
                payload["messages"] = payload_messages
                # Also add parentMessageIds to userMessage if we have history
                if parent_ids:
                    payload["userMessage"]["parentMessageIds"] = parent_ids

            debug_print(f"📤 Preparing Chunk {chunk_index + 1}/{total_chunks} (Size: {len(final_content)})")
            return payload, user_msg_obj, model_msg_obj

        # Handle streaming mode
        if stream:
            async def generate_stream():
                try:
                    debug_print("🌊 generate_stream started")
                    chunk_id = f"chatcmpl-{uuid.uuid4()}"
                    
                    current_headers = None
                    current_session_id = None
                    
                    # --- BROWSER CONSISTENCY ---
                    # We must use Firefox to match the cf_clearance cookie obtained by Camoufox.
                    # Randomizing this will break the Cloudflare session.
                    
                    for i, chunk in enumerate(chunks):
                        # --- ROTATION LOGIC ---
                        is_new_session = False
                        if i % CHUNK_ROTATION_LIMIT == 0:
                            debug_print(f"🔄 Batch Rotation: Switching to New Token & Session for Chunk {i+1}")
                            
                            # --- STICKY SESSION LOGIC ---
                            sticky_key = f"{api_key_str}:{model_public_name}"
                            if STICKY_SESSIONS and sticky_key in sticky_session_ids:
                                data = sticky_session_ids[sticky_key]
                                current_session_id = data["session_id"]
                                current_headers = data["headers"]
                                debug_print(f"📎 Reusing Sticky Session ID: {current_session_id}")
                                is_new_session = False
                            else:
                                current_headers = get_request_headers()
                                current_session_id = str(uuid7())
                                if STICKY_SESSIONS:
                                    sticky_session_ids[sticky_key] = {
                                        "session_id": current_session_id,
                                        "headers": current_headers
                                    }
                                    debug_print(f"📎 Created New Sticky Session ID: {current_session_id}")
                                is_new_session = True
                            
                            # --- FUTURE PROOFING: Thinking Delay ---
                            # Add a small random delay for the first chunk of a new session to mimic human thinking
                            if i == 0:
                                think_delay = random.uniform(0.5, 1.5)
                                debug_print(f"🤔 Thinking delay: {think_delay:.2f}s")
                                await asyncio.sleep(think_delay)
                        
                        # --- RETRY LOOP FOR 429s/401s ---
                        for attempt in range(5):
                            # Filter headers to let curl_cffi handle browser fingerprinting
                            # We only pass essential headers that carry state or content info.
                            # IMPORTANT: Do NOT pass User-Agent here, let curl_cffi set it to match the impersonation target.
                            chunk_headers = {
                                "Cookie": current_headers.get("Cookie"),
                                "Content-Type": current_headers.get("Content-Type"),
                                "Referer": current_headers.get("Referer"),
                                "Origin": current_headers.get("Origin"),
                                # "User-Agent": current_headers.get("User-Agent"), # REMOVED to prevent fingerprint mismatch
                            }
                            # Remove None values
                            chunk_headers = {k: v for k, v in chunk_headers.items() if v is not None}
                            
                            # Extract and log token index
                            token_match = re.search(r'arena-auth-prod-v1=([^;]+)', chunk_headers.get("Cookie", ""))
                            token_display = "Unknown"
                            if token_match:
                                current_token = token_match.group(1)
                                try:
                                    _tokens = get_config().get("auth_tokens", [])
                                    if current_token in _tokens:
                                        token_display = f"#{_tokens.index(current_token) + 1}"
                                    else:
                                        token_display = "Unlisted"
                                except: pass
                            
                            debug_print(f"📋 Chunk {i+1} | Token {token_display} | Session: {current_session_id}")

                            is_last = (i == len(chunks) - 1)
                            payload, user_msg, model_msg = await get_chunk_payload(i, chunk, is_last, current_session_id, is_new_session)
                            
                            # Store response text for this chunk to update history
                            current_response_text = ""
                            
                            try:
                                # Use curl_cffi to impersonate Firefox to match AsyncCamoufox's cookies
                                async with AsyncSession() as client:
                                    # Note: curl_cffi stream API is slightly different
                                    response = await client.post(url, json=payload, headers=chunk_headers, timeout=120, stream=True)
                                    
                                    if response.status_code == 403:
                                        debug_print(f"❌ 403 Forbidden. Response: {await response.atext()}")
                                        # Try to print headers to see what we sent
                                        debug_print(f"   Sent Headers: {chunk_headers.keys()}")
                                        debug_print(f"   Sent Cookie: {chunk_headers.get('Cookie')[:50]}...")
                                    
                                    # HANDLE 429 (Rate Limit), 401 (Unauthorized), and 403 (Forbidden)
                                    if response.status_code in [429, 401, 403]:
                                        error_type = "Rate Limit" if response.status_code == 429 else "Auth Error"
                                        debug_print(f"⚠️ {response.status_code} ({error_type}) on Chunk {i+1}")

                                        # If we get an error on a sticky session, it means the session/token is dead.
                                        if STICKY_SESSIONS and sticky_key in sticky_session_ids:
                                            debug_print(f"   Invalidating Sticky Session {current_session_id}...")
                                            del sticky_session_ids[sticky_key]
                                        
                                        # Only retry if we haven't exhausted attempts
                                        if attempt < 4:
                                            debug_print(f"♻️ Rotating to NEXT token/session and retrying (Attempt {attempt+2}/5)...")
                                            
                                            # Force a small cool-down to avoid hammering
                                            await asyncio.sleep(2)
                                            
                                            # Generate new identity
                                            current_headers = get_request_headers() # This gets the NEXT token in the list
                                            current_session_id = str(uuid7())
                                            is_new_session = True # Force history resend for new session
                                            
                                            if STICKY_SESSIONS:
                                                sticky_session_ids[sticky_key] = {
                                                    "session_id": current_session_id,
                                                    "headers": current_headers
                                                }
                                            continue # Retry loop
                                        
                                        # If we ran out of retries, raise the error
                                        raise HTTPException(status_code=response.status_code, detail=f"Upstream error: {response.status_code}")

                                    if response.status_code >= 400:
                                        raise HTTPException(status_code=response.status_code, detail=f"Upstream error: {response.status_code}")

                                    if not is_last:
                                        # Consume intermediate chunks
                                        async for line in response.aiter_lines():
                                            line = line.decode('utf-8').strip() if isinstance(line, bytes) else line.strip()
                                            if line.startswith("a0:"):
                                                try:
                                                    text_chunk = json.loads(line[3:])
                                                    current_response_text += text_chunk
                                                except: 
                                                    pass
                                            
                                            # Update history
                                            user_msg["status"] = "success"
                                            model_msg["content"] = current_response_text
                                            model_msg["status"] = "success"
                                            
                                        # Log ONCE after loop
                                        debug_print(f"✅ Intermediate chunk {i+1} sent. Response len: {len(current_response_text)}")
                                        local_messages.append(user_msg)
                                        local_messages.append(model_msg)
                                        
                                        await asyncio.sleep(0.5)
                                    else:
                                        # Stream final chunk
                                        async for line in response.aiter_lines():
                                            line = line.decode('utf-8').strip() if isinstance(line, bytes) else line.strip()
                                            if not line: continue
                                            
                                            if line.startswith("a0:"):
                                                chunk_data = line[3:]
                                                try:
                                                    text_chunk = json.loads(chunk_data)
                                                    current_response_text += text_chunk
                                                    
                                                    chunk_response = {
                                                        "id": chunk_id,
                                                        "object": "chat.completion.chunk",
                                                        "created": int(time.time()),
                                                        "model": model_public_name,
                                                        "choices": [{"index": 0, "delta": {"content": text_chunk}, "finish_reason": None}]
                                                    }
                                                    yield f"data: {json.dumps(chunk_response)}\n\n"
                                                except: pass
                                            elif line.startswith("ad:"):
                                                try:
                                                    metadata = json.loads(line[3:])
                                                    finish_reason = metadata.get("finishReason", "stop")
                                                    final_chunk = {
                                                        "id": chunk_id,
                                                        "object": "chat.completion.chunk",
                                                        "created": int(time.time()),
                                                        "model": model_public_name,
                                                        "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}]
                                                    }
                                                    yield f"data: {json.dumps(final_chunk)}\n\n"
                                                except: pass
                                            elif line.startswith("a3:"):
                                                error_data = line[3:]
                                                try:
                                                    error_message = json.loads(error_data)
                                                    print(f"  ❌ Error in stream: {error_message}")
                                                    error_chunk = {
                                                        "error": {
                                                            "message": str(error_message),
                                                            "type": "api_error",
                                                            "code": 500
                                                        }
                                                    }
                                                    yield f"data: {json.dumps(error_chunk)}\n\n"
                                                except: pass
                                        
                                        # Update history (though not strictly needed for final chunk unless we want to save it)
                                        user_msg["status"] = "success"
                                        model_msg["content"] = current_response_text
                                        model_msg["status"] = "success"
                                        local_messages.append(user_msg)
                                        local_messages.append(model_msg)
                                                
                                        yield "data: [DONE]\n\n"
                                        debug_print(f"✅ Stream completed")
                                    
                                    # Success - break retry loop
                                    break

                            except (HTTPError, Timeout, RequestsError) as e:
                                print(f"❌ Stream error (curl_cffi): {str(e)}")
                                
                                if attempt < 4:
                                    debug_print(f"⚠️ Connection error on Chunk {i+1}. Rotating and retrying (Attempt {attempt+2}/5)...")
                                    
                                    if STICKY_SESSIONS and sticky_key in sticky_session_ids:
                                        debug_print(f"   Invalidating Sticky Session {current_session_id}...")
                                        del sticky_session_ids[sticky_key]
                                    
                                    await asyncio.sleep(2)
                                    current_headers = get_request_headers()
                                    current_session_id = str(uuid7())
                                    is_new_session = True
                                    
                                    if STICKY_SESSIONS:
                                        sticky_session_ids[sticky_key] = {
                                            "session_id": current_session_id,
                                            "headers": current_headers
                                        }
                                    continue # Retry loop

                                error_chunk = {
                                    "error": {
                                        "message": f"Upstream error: {str(e)}",
                                        "type": "upstream_error",
                                        "code": 502
                                    }
                                }
                                yield f"data: {json.dumps(error_chunk)}\n\n"
                                debug_print(f"⛔ Chunk {i+1} failed after {attempt+1} attempts. Aborting stream.")
                                return # Stop the stream completely to avoid sending a broken prompt
                            except Exception as e:
                                print(f"❌ Stream error (general): {str(e)}")
                                error_chunk = {
                                    "error": {
                                        "message": str(e),
                                        "type": "internal_error"

                                    }
                                }
                                yield f"data: {json.dumps(error_chunk)}\n\n"
                                break # Break retry loop
                finally:
                    global active_generations
                    active_generations -= 1
                    debug_print(f"🌊 generate_stream finished. Active generations: {active_generations}")
            
            debug_print("🚀 Starting StreamingResponse...")
            should_decrement = False
            return StreamingResponse(generate_stream(), media_type="text/event-stream")
        
        # Handle non-streaming mode
        # Use curl_cffi for non-streaming as well
        try:
            # --- BROWSER CONSISTENCY ---

            async with AsyncSession() as client:
                final_response = None
                
                current_headers = None
                current_session_id = None
                
                for i, chunk in enumerate(chunks):
                    # --- ROTATION LOGIC ---
                    is_new_session = False
                    if i % CHUNK_ROTATION_LIMIT == 0:
                        debug_print(f"🔄 Batch Rotation: Switching to New Token & Session for Chunk {i+1}")
                        
                        # --- STICKY SESSION LOGIC ---
                        sticky_key = f"{api_key_str}:{model_public_name}"
                        if STICKY_SESSIONS and sticky_key in sticky_session_ids:
                            data = sticky_session_ids[sticky_key]
                            current_session_id = data["session_id"]
                            current_headers = data["headers"]
                            debug_print(f"📎 Reusing Sticky Session ID: {current_session_id}")
                            is_new_session = False
                        else:
                            current_headers = get_request_headers()
                            current_session_id = str(uuid7())
                            if STICKY_SESSIONS:
                                sticky_session_ids[sticky_key] = {
                                    "session_id": current_session_id,
                                    "headers": current_headers
                                }
                                debug_print(f"📎 Created New Sticky Session ID: {current_session_id}")
                            is_new_session = True
                        
                        # --- FUTURE PROOFING: Thinking Delay ---
                        if i == 0:
                            think_delay = random.uniform(0.5, 1.5)
                            debug_print(f"🤔 Thinking delay: {think_delay:.2f}s")
                            await asyncio.sleep(think_delay)

                    # --- RETRY LOOP FOR 429s/401s ---
                    for attempt in range(5):
                        chunk_headers = {
                            "Cookie": current_headers.get("Cookie"),
                            "Content-Type": current_headers.get("Content-Type"),
                            "Referer": current_headers.get("Referer"),
                            "Origin": current_headers.get("Origin"),
                            # "User-Agent": current_headers.get("User-Agent"), # REMOVED
                        }
                        chunk_headers = {k: v for k, v in chunk_headers.items() if v is not None}

                        # Extract and log token index
                        token_match = re.search(r'arena-auth-prod-v1=([^;]+)', chunk_headers.get("Cookie", ""))
                        token_display = "Unknown"
                        if token_match:
                            current_token = token_match.group(1)
                            try:
                                _tokens = get_config().get("auth_tokens", [])
                                if current_token in _tokens:
                                    token_display = f"#{_tokens.index(current_token) + 1}"
                                else:
                                    token_display = "Unlisted"
                            except: pass
                        
                        debug_print(f"📋 Chunk {i+1} | Token {token_display} | Session: {current_session_id}")

                        is_last = (i == len(chunks) - 1)
                        payload, user_msg, model_msg = await get_chunk_payload(i, chunk, is_last, current_session_id, is_new_session)
                        
                        current_response_text = ""
                        finish_reason = "stop"
                        error_message = None
                        
                        try:
                            debug_print(f"📡 Sending POST request for chunk {i+1}...")
                            response = await client.post(url, json=payload, headers=chunk_headers, timeout=120)
                            
                            # HANDLE 429 (Rate Limit), 401 (Unauthorized), and 403 (Forbidden)
                            if response.status_code in [429, 401, 403]:
                                error_type = "Rate Limit" if response.status_code == 429 else "Auth Error"
                                debug_print(f"⚠️ {response.status_code} ({error_type}) on Chunk {i+1}")

                                if STICKY_SESSIONS and sticky_key in sticky_session_ids:
                                    debug_print(f"   Invalidating Sticky Session {current_session_id}...")
                                    del sticky_session_ids[sticky_key]
                                
                                if attempt < 4:
                                    debug_print(f"♻️ Rotating to NEXT token/session and retrying (Attempt {attempt+2}/5)...")
                                    await asyncio.sleep(2)
                                    current_headers = get_request_headers()
                                    current_session_id = str(uuid7())
                                    is_new_session = True
                                    
                                    if STICKY_SESSIONS:
                                        sticky_session_ids[sticky_key] = {
                                            "session_id": current_session_id,
                                            "headers": current_headers
                                        }
                                    continue # Retry loop
                            
                            if not is_last:
                                response.raise_for_status()
                                
                                # Parse response to get content for history
                                for line in response.text.splitlines():
                                    line = line.strip()
                                    if line.startswith("a0:"):
                                        try:
                                            text_chunk = json.loads(line[3:])
                                            current_response_text += text_chunk
                                        except: pass
                                
                                debug_print(f"✅ Intermediate chunk {i+1} sent. Response len: {len(current_response_text)}")
                                
                                # Update history
                                user_msg["status"] = "success"
                                model_msg["content"] = current_response_text
                                model_msg["status"] = "success"
                                local_messages.append(user_msg)
                                local_messages.append(model_msg)
                                
                                await asyncio.sleep(0.5)
                                break # Success, break retry loop and continue to next chunk
                            
                            # Process final response
                            debug_print(f"✅ Final response received - Status: {response.status_code}")
                            response.raise_for_status()
                            
                            for line in response.text.splitlines():
                                line = line.strip()
                                if not line: continue
                                
                                if line.startswith("a0:"):
                                    chunk_data = line[3:]
                                    try:
                                        text_chunk = json.loads(chunk_data)
                                        current_response_text += text_chunk
                                    except: pass
                                elif line.startswith("a3:"):
                                    error_data = line[3:]
                                    try:
                                        error_message = json.loads(error_data)
                                    except: error_message = error_data
                                elif line.startswith("ad:"):
                                    try:
                                        metadata = json.loads(line[3:])
                                        finish_reason = metadata.get("finishReason", "stop")
                                    except: pass

                            if not current_response_text and error_message:
                                return {
                                    "error": {
                                        "message": f"Proxy error: {error_message}",
                                        "type": "upstream_error",
                                        "code": "lmarena_error"
                                    }
                                }
                            
                            # Update session (for final chunk)
                            user_msg["status"] = "success"
                            model_msg["content"] = current_response_text
                            model_msg["status"] = "success"
                            local_messages.append(user_msg)
                            local_messages.append(model_msg)
                            
                            # Save to global session (optional, but good for debugging)
                            if conversation_id not in chat_sessions[api_key_str]:
                                chat_sessions[api_key_str][conversation_id] = {
                                    "conversation_id": payload["id"], # Use last eval ID
                                    "model": model_public_name,
                                    "messages": local_messages
                                }

                            final_response = {
                                "id": f"chatcmpl-{uuid.uuid4()}",
                                "object": "chat.completion",
                                "created": int(time.time()),
                                "model": model_public_name,
                                "conversation_id": conversation_id,
                                "choices": [{
                                    "index": 0,
                                    "message": {
                                        "role": "assistant",
                                        "content": current_response_text.strip(),
                                    },
                                    "finish_reason": finish_reason
                                }],
                                "usage": {
                                    "prompt_tokens": len(prompt),
                                    "completion_tokens": len(current_response_text),
                                    "total_tokens": len(prompt) + len(current_response_text)
                                }
                            }
                            
                            debug_print(f"\n✅ REQUEST COMPLETED SUCCESSFULLY")
                            debug_print("="*80 + "\n")
                            
                            return final_response
                        
                        except HTTPError as e:
                            error_detail = f"Sayori Proxy error: {e.response.status_code}"
                            try:
                                error_body = e.response.json()
                                error_detail += f" - {error_body}"
                            except:
                                error_detail += f" - {e.response.text[:200]}"
                            print(f"\n❌ HTTP STATUS ERROR (curl_cffi)")
                            print(f"📛 Error detail: {error_detail}")
                            
                            error_type = "rate_limit_error" if e.response.status_code == 429 else "upstream_error"
                            return {
                                "error": {
                                    "message": "The API is overloaded at the moment. Try again later.",
                                    "type": error_type,
                                    "code": f"http_{e.response.status_code}"
                                }
                            }
                        
                        except Timeout as e:
                            print(f"\n⏱️  TIMEOUT ERROR (curl_cffi)")
                            return {
                                "error": {
                                    "message": "Request to Sayori Proxy timed out after 120 seconds",
                                    "type": "timeout_error",
                                    "code": "request_timeout"
                                }
                            }
                        
                        except Exception as e:
                            print(f"\n❌ UNEXPECTED ERROR IN HTTP CLIENT")
                            print(f"📛 Error type: {type(e).__name__}")
                            print(f"📛 Error message: {str(e)}")
                            return {
                                "error": {
                                    "message": "Unexpected error in HTTP Client.}",
                                    "type": "internal_error",
                                    "code": type(e).__name__.lower()
                                }
                            }
        finally:
            pass
                
    except HTTPException:
        raise
    except Exception as e:
        print(f"\n❌ TOP-LEVEL EXCEPTION")
        print(f"📛 Error type: {type(e).__name__}")
        print(f"📛 Error message: {str(e)}")
        traceback.print_exc()
        print("="*80 + "\n")
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        if should_decrement:
            active_generations -= 1

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Server Starting...")
    print("=" * 60)
    print(f"📍 Dashboard: http://localhost:{PORT}/dashboard")
    print(f"🔐 Login: http://localhost:{PORT}/login")
    print(f"📚 API Base URL: http://localhost:{PORT}/v1")
    print("=" * 60)
    try:
        uvicorn.run(app, host="0.0.0.0", port=PORT)
    except Exception as e:
        print(f"❌ Uvicorn crashed: {e}")
        traceback.print_exc()
