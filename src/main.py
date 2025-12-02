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
from http.cookies import SimpleCookie
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
from curl_cffi.requests.exceptions import HTTPError, Timeout, RequestException as RequestsError, ConnectionError, ImpersonateError

# ============================================================
# CONFIGURATION
# ============================================================
# Set to True for detailed logging, False for minimal logging
DEBUG = True

# Port to run the server on
PORT = 8081

# Chunk size for splitting large prompts (characters)
CHUNK_SIZE = 110000

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

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
# Server start time for uptime tracking
server_start_time = time.time()
# Total tokens generated (approximate using tiktoken)
total_tokens_generated = 0

# --- Log Buffer for Dashboard ---
# Circular buffer to store recent log messages
LOG_BUFFER_SIZE = 500
log_buffer: List[dict] = []
log_buffer_lock = asyncio.Lock()

# --- Token Collection State ---
token_collection_status = {
    "running": False,
    "collected": 0,
    "target": 0,
    "current_status": "Idle",
    "errors": []
}

async def add_log(message: str, level: str = "INFO"):
    """Add a log message to the buffer (async version)"""
    global log_buffer
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = {
        "timestamp": timestamp,
        "level": level,
        "message": message
    }
    async with log_buffer_lock:
        log_buffer.append(log_entry)
        if len(log_buffer) > LOG_BUFFER_SIZE:
            log_buffer = log_buffer[-LOG_BUFFER_SIZE:]
    # Also print to console
    print(f"[{timestamp}] [{level}] {message}")

def sync_log(message: str, level: str = "INFO"):
    """Add a log message to the buffer (sync version for non-async code)"""
    global log_buffer
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = {
        "timestamp": timestamp,
        "level": level,
        "message": message
    }
    # Use blocking append (safe for single-threaded async)
    log_buffer.append(log_entry)
    if len(log_buffer) > LOG_BUFFER_SIZE:
        log_buffer = log_buffer[-LOG_BUFFER_SIZE:]
    # Also print to console
    print(f"[{timestamp}] [{level}] {message}")

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
    
    # Generation parameters defaults (used when frontend doesn't specify)
    config.setdefault("default_temperature", 0.7)
    config.setdefault("default_top_p", 1.0)
    config.setdefault("default_max_tokens", 64000)
    
    # Token auto-collection settings
    config.setdefault("token_collect_count", 15)
    config.setdefault("token_collect_delay", 2)  # seconds between collections
    
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

# --- reCAPTCHA TOKEN CACHING ---
# reCAPTCHA v3 tokens are valid for ~2 minutes (120s)
# We cache for 110 seconds to stay safely within the limit
RECAPTCHA_TOKEN_CACHE_TTL = 100  # seconds
cached_recaptcha_token = None
cached_recaptcha_timestamp = 0

def get_request_headers():
    global current_token_index
    
    config = get_config()
    auth_tokens = config.get("auth_tokens", [])

    # Fallback to single token for backwards compatibility
    if not auth_tokens:
        raise HTTPException(status_code=500, detail="No arena auth tokens configured.")
    
    # Round-robin token selection - save index BEFORE incrementing for correct display
    token_index_used = current_token_index % len(auth_tokens)
    token = auth_tokens[token_index_used]
    current_token_index = (current_token_index + 1) % len(auth_tokens)

    sync_log(f"🔑 Using Token #{token_index_used + 1}/{len(auth_tokens)}", "DEBUG")
    
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
    await add_log("🔄 Starting initial data retrieval...", "INFO")
    
    # Close previous page if it exists
    if global_page:
        try:
            await add_log("♻️ Closing previous page...", "DEBUG")
            await global_page.close()
        except Exception as e:
            await add_log(f"⚠️ Failed to close previous page: {e}", "WARN")
    
    try:
        # Enable geoip to look more legitimate
        # async with AsyncCamoufox(headless=True, geoip=True) as browser:
        if True: # Preserve indentation level
            if global_browser is None:
                await add_log("🚀 Initializing global browser instance...", "INFO")
                # Add args to disable WebGL to prevent RenderCompositorSWGL crashes
                global_browser = await AsyncCamoufox(
                    headless=True, 
                    geoip=True,
                    args=["--disable-webgl", "--disable-gl-drawing-for-tests"]
                ).__aenter__()
            browser = global_browser

            # Create context with ignore_https_errors to prevent SSL crashes
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
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
            await add_log(f"🕵️ User Agent: {user_agent[:60]}...", "DEBUG")
            
            await add_log("🌐 Navigating to lmarena.ai...", "INFO")

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
                await add_log(f"⚠️ Navigation timeout (continuing): {e}", "WARN")

            await add_log("⏳ Waiting for Cloudflare challenge...", "INFO")
            try:
                # Wait a bit for the challenge to load
                await asyncio.sleep(3 + random.random())
                
                # 2. Humanize: Random mouse movements
                await page.mouse.move(random.randint(100, 500), random.randint(100, 500))
                await asyncio.sleep(0.5)
                await page.mouse.move(random.randint(100, 500), random.randint(100, 500), steps=10)
        
                # Look for Cloudflare Turnstile checkbox/widget
                await add_log("🔍 Looking for Cloudflare Turnstile iframe...", "DEBUG")
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
                    await add_log(f"✅ Found Turnstile frame: {turnstile_frame.url[:60]}...", "SUCCESS")
                    await asyncio.sleep(random.uniform(2.0, 4.0)) # Wait longer for content to render
                    
                    # DEBUG: Print frame content to understand structure
                    try:
                        frame_content = await turnstile_frame.content()
                        await add_log(f"🔍 Frame content preview: {frame_content[:150]}...", "DEBUG")
                    except Exception as e:
                        await add_log(f"⚠️ Could not read frame content: {e}", "DEBUG")

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
                                await add_log(f"✅ Found checkbox with selector: {sel}", "SUCCESS")
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
                            
                            await add_log(f"🖱️ Moving to checkbox at ({int(x)}, {int(y)})...", "DEBUG")
                            await page.mouse.move(x, y, steps=random.randint(15, 25))
                            await asyncio.sleep(random.uniform(0.3, 0.6))
                            
                            await add_log("🖱️ Clicking checkbox...", "DEBUG")
                            await page.mouse.down()
                            await asyncio.sleep(random.uniform(0.05, 0.15))
                            await page.mouse.up()
                        else:
                            await add_log("⚠️ Checkbox has no bounding box, clicking blindly", "WARN")
                            await checkbox.click()
                    else:
                        await add_log("⚠️ No checkbox found, clicking at iframe position...", "WARN")
                        
                        # NEW: Click at the CHECKBOX position within the iframe (left side)
                        # The Turnstile checkbox is always on the left side of the widget
                        clicked_checkbox = False
                        
                        # Try to get iframe bounding box and click at checkbox position
                        try:
                            iframes = await page.query_selector_all('iframe')
                            await add_log(f"🔍 Found {len(iframes)} iframes on page", "DEBUG")
                            
                            for iframe_el in iframes:
                                src = await iframe_el.get_attribute('src') or ""
                                if "challenges.cloudflare.com" in src or "turnstile" in src.lower():
                                    box = await iframe_el.bounding_box()
                                    if box:
                                        # Checkbox is at left side of iframe, about 28px in
                                        cx = box['x'] + 28
                                        cy = box['y'] + box['height'] / 2
                                        
                                        await add_log(f"🎯 Turnstile iframe: ({int(box['x'])}, {int(box['y'])}) {int(box['width'])}x{int(box['height'])}", "DEBUG")
                                        await add_log(f"🖱️ Clicking at ({int(cx)}, {int(cy)})...", "DEBUG")
                                        
                                        await page.mouse.move(cx, cy, steps=random.randint(10, 20))
                                        await asyncio.sleep(random.uniform(0.2, 0.5))
                                        await page.mouse.click(cx, cy)
                                        await add_log("✅ Clicked Turnstile checkbox position!", "SUCCESS")
                                        clicked_checkbox = True
                                        break
                        except Exception as e:
                            await add_log(f"⚠️ Iframe click failed: {e}", "WARN")
                        
                        # Fallback: Try frame body click
                        if not clicked_checkbox:
                            try:
                                body = await turnstile_frame.query_selector('body')
                                if body:
                                    box = await body.bounding_box()
                                    if box:
                                        # Click at checkbox position (left side)
                                        cx = box['x'] + 28
                                        cy = box['y'] + box['height'] / 2
                                        await page.mouse.click(cx, cy)
                                        await add_log(f"🖱️ Clicked frame body at ({int(cx)}, {int(cy)})", "DEBUG")
                                    else:
                                        await body.click()
                                        await add_log("🖱️ Clicked frame body (center)", "DEBUG")
                            except Exception as e:
                                await add_log(f"⚠️ Frame body click failed: {e}", "WARN")

                else:
                    await add_log("⚠️ Turnstile frame NOT found in page frames", "WARN")
                    # Last resort: Check if there is a 'Verify you are human' text and click near it?
                    pass
        
                # Now wait for challenge to complete
                current_title = await page.title()
                await add_log(f"⏳ Waiting for challenge... Title: '{current_title}'", "DEBUG")

                await page.wait_for_function(
                    "() => document.title.indexOf('Just a moment...') === -1", 
                    timeout=60000 # Increased timeout
                )
                await add_log("✅ Cloudflare challenge passed!", "SUCCESS")
        
                await asyncio.sleep(4 + random.random())
            except Exception as e:
                await add_log(f"❌ Cloudflare challenge failed: {e}", "ERROR")
                
                # Handle browser closed error
                if "closed" in str(e) or "Connection closed" in str(e):
                    await add_log("♻️ Browser closed unexpectedly. Resetting...", "WARN")
                    global_browser = None
                    global_page = None
                    # Optional: Retry immediately?
                    # await get_initial_data() 
                    return

                # Verbose error logging
                try:
                    error_title = await page.title()
                    error_url = page.url
                    text_content = await page.evaluate("document.body.innerText")
                    
                    await add_log(f"🔍 Debug - URL: {error_url}", "DEBUG")
                    await add_log(f"🔍 Debug - Title: {error_title}", "DEBUG")
                    await add_log(f"🔍 Debug - Text: {text_content[:200].replace(chr(10), ' ')}...", "DEBUG")
                    
                    if "Access denied" in text_content:
                        await add_log("⚠️ Detected 'Access denied' message", "ERROR")
                    if "Challenge Validation failed" in text_content:
                        await add_log("⚠️ Detected 'Challenge Validation failed'", "ERROR")
                        
                    # Check for iframes
                    frames = page.frames
                    await add_log(f"🔍 Debug - {len(frames)} frames on page", "DEBUG")
                            
                except Exception as debug_e:
                    await add_log(f"⚠️ Failed to capture debug info: {debug_e}", "DEBUG")
                
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
                    await add_log("✅ Found __cf_bm cookie", "DEBUG")
            
            full_cookie_string = "; ".join(cookie_parts)
            
            config = get_config()
            # Save cookies even if cf_clearance is missing, as __cf_bm might be enough for some checks
            # or we might have passed the challenge but the cookie hasn't appeared yet (unlikely if we waited)
            if cookies:
                config["cf_clearance"] = next((c['value'] for c in cookies if c['name'] == "cf_clearance"), "")
                config["cookie_string"] = full_cookie_string
                config["user_agent"] = user_agent
                save_config(config)
                await add_log(f"✅ Saved cookie session ({len(cookies)} cookies)", "SUCCESS")
            else:
                await add_log("⚠️ No cookies found to save", "WARN")

            # Extract models
            await add_log("📋 Extracting models from page...", "INFO")
            try:
                body = await page.content()
                match = re.search(r'{\\"initialModels\\":(\[.*?\]),\\"initialModel[A-Z]Id', body, re.DOTALL)
                if match:
                    models_json = match.group(1).encode().decode('unicode_escape')
                    models = json.loads(models_json)
                    save_models(models)
                    await add_log(f"✅ Loaded {len(models)} models from LMArena", "SUCCESS")
                else:
                    await add_log("⚠️ Could not find models in page", "WARN")
            except Exception as e:
                await add_log(f"❌ Error extracting models: {e}", "ERROR")

            # --- NEW: Extract reCAPTCHA Token ---
            # Moved to refresh_recaptcha_token() called in api_chat_completions
            # ----------------------------------------

    except Exception as e:
        await add_log(f"❌ Initial data retrieval error: {e}", "ERROR")
        # Check if the error is related to the browser being closed
        if "Target page, context or browser has been closed" in str(e) or "Connection closed" in str(e):
            await add_log("⚠️ Browser connection lost. Resetting...", "WARN")
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
    # Log startup
    await add_log("🚀 LMArena Bridge starting up...", "INFO")
    await add_log(f"📍 Dashboard: http://localhost:{PORT}/dashboard", "INFO")
    await add_log(f"📚 API Base URL: http://localhost:{PORT}/v1", "INFO")
    # Start initial data fetch
    asyncio.create_task(get_initial_data())
    # Start periodic refresh task (every 30 minutes)
    asyncio.create_task(periodic_refresh_task())
    await add_log("✅ Startup complete", "SUCCESS")

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
    
    error_msg = '<div class="error-message">❌ Invalid password. Please try again.</div>' if error else ''
    
    return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - LMArena Bridge</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                :root {{
                    --primary: #6366f1;
                    --primary-dark: #4f46e5;
                    --secondary: #8b5cf6;
                    --bg: #0f172a;
                    --bg-card: #1e293b;
                    --bg-input: #334155;
                    --text: #f1f5f9;
                    --text-muted: #94a3b8;
                    --border: #475569;
                    --danger: #ef4444;
                }}
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: var(--bg);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }}
                .login-wrapper {{
                    text-align: center;
                }}
                .logo {{
                    font-size: 48px;
                    margin-bottom: 16px;
                }}
                .brand-title {{
                    font-size: 32px;
                    font-weight: 700;
                    color: var(--text);
                    margin-bottom: 8px;
                }}
                .brand-subtitle {{
                    color: var(--text-muted);
                    font-size: 14px;
                    margin-bottom: 32px;
                }}
                .login-container {{
                    background: var(--bg-card);
                    padding: 40px;
                    border-radius: 16px;
                    border: 1px solid var(--border);
                    width: 100%;
                    max-width: 400px;
                }}
                h2 {{
                    color: var(--text);
                    margin-bottom: 8px;
                    font-size: 24px;
                    font-weight: 600;
                }}
                .subtitle {{
                    color: var(--text-muted);
                    margin-bottom: 24px;
                    font-size: 14px;
                }}
                .form-group {{
                    margin-bottom: 20px;
                    text-align: left;
                }}
                label {{
                    display: block;
                    margin-bottom: 8px;
                    color: var(--text-muted);
                    font-weight: 500;
                    font-size: 13px;
                }}
                input[type="password"] {{
                    width: 100%;
                    padding: 14px 16px;
                    background: var(--bg-input);
                    border: 1px solid var(--border);
                    border-radius: 10px;
                    font-size: 14px;
                    color: var(--text);
                    transition: all 0.2s;
                }}
                input[type="password"]::placeholder {{
                    color: var(--text-muted);
                }}
                input[type="password"]:focus {{
                    outline: none;
                    border-color: var(--primary);
                    box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
                }}
                button {{
                    width: 100%;
                    padding: 14px;
                    background: var(--primary);
                    color: white;
                    border: none;
                    border-radius: 10px;
                    font-size: 14px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.2s;
                }}
                button:hover {{
                    background: var(--primary-dark);
                    transform: translateY(-2px);
                }}
                button:active {{
                    transform: translateY(0);
                }}
                .error-message {{
                    background: rgba(239, 68, 68, 0.1);
                    color: #fca5a5;
                    padding: 12px 16px;
                    border-radius: 10px;
                    margin-bottom: 20px;
                    border-left: 4px solid var(--danger);
                    font-size: 14px;
                    text-align: left;
                }}
                .credits {{
                    margin-top: 24px;
                    color: var(--text-muted);
                    font-size: 13px;
                }}
                .credits a {{
                    color: var(--primary);
                    text-decoration: none;
                }}
                .credits a:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <div class="login-wrapper">
                <div class="logo">🚀</div>
                <h1 class="brand-title">LMArena Bridge</h1>
                <p class="brand-subtitle">High-performance LMArena API proxy</p>
                
                <div class="login-container">
                    <h2>Welcome Back</h2>
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
                
                <div class="credits">
                    By: <a href="#">@rumoto</a> and <a href="#">@norenaboi</a>
                </div>
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

def get_uptime_string():
    """Get human-readable uptime string"""
    uptime_seconds = int(time.time() - server_start_time)
    days, remainder = divmod(uptime_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    
    return " ".join(parts)

def format_tokens(count):
    """Format token count with K/M suffix"""
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    elif count >= 1_000:
        return f"{count / 1_000:.1f}K"
    return str(count)

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
                        <button type='submit' class='btn btn-danger'>Delete</button>
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
                            <button type='submit' class='btn btn-danger'>Delete</button>
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
    
    # Get generation params
    default_temp = config.get("default_temperature", 0.7)
    default_top_p = config.get("default_top_p", 1.0)
    default_max_tokens = config.get("default_max_tokens", 64000)
    
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
                :root {{
                    --primary: #6366f1;
                    --primary-dark: #4f46e5;
                    --secondary: #8b5cf6;
                    --success: #10b981;
                    --warning: #f59e0b;
                    --danger: #ef4444;
                    --bg: #0f172a;
                    --bg-card: #1e293b;
                    --bg-input: #334155;
                    --text: #f1f5f9;
                    --text-muted: #94a3b8;
                    --border: #475569;
                }}
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: var(--bg);
                    color: var(--text);
                    line-height: 1.6;
                    min-height: 100vh;
                }}
                
                /* Layout */
                .layout {{
                    display: grid;
                    grid-template-columns: 260px 1fr;
                    min-height: 100vh;
                }}
                
                /* Sidebar */
                .sidebar {{
                    background: var(--bg-card);
                    border-right: 1px solid var(--border);
                    padding: 24px;
                    position: sticky;
                    top: 0;
                    height: 100vh;
                    overflow-y: auto;
                }}
                .logo {{
                    font-size: 20px;
                    font-weight: 700;
                    color: var(--text);
                    margin-bottom: 32px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }}
                .nav-section {{
                    margin-bottom: 24px;
                }}
                .nav-label {{
                    font-size: 11px;
                    text-transform: uppercase;
                    color: var(--text-muted);
                    letter-spacing: 1px;
                    margin-bottom: 12px;
                }}
                .nav-link {{
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    padding: 10px 12px;
                    border-radius: 8px;
                    color: var(--text-muted);
                    text-decoration: none;
                    font-size: 14px;
                    transition: all 0.2s;
                    cursor: pointer;
                }}
                .nav-link:hover, .nav-link.active {{
                    background: var(--primary);
                    color: white;
                }}
                .nav-link svg {{
                    width: 18px;
                    height: 18px;
                }}
                
                /* Main Content */
                .main {{
                    padding: 32px;
                    overflow-y: auto;
                }}
                .page-header {{
                    margin-bottom: 32px;
                }}
                .page-title {{
                    font-size: 28px;
                    font-weight: 700;
                    margin-bottom: 8px;
                }}
                .page-subtitle {{
                    color: var(--text-muted);
                    font-size: 14px;
                }}
                
                /* Stats Grid */
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 32px;
                }}
                .stat-card {{
                    background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
                    padding: 24px;
                    border-radius: 16px;
                    position: relative;
                    overflow: hidden;
                }}
                .stat-card::before {{
                    content: '';
                    position: absolute;
                    top: -50%;
                    right: -50%;
                    width: 100%;
                    height: 100%;
                    background: rgba(255,255,255,0.1);
                    border-radius: 50%;
                }}
                .stat-value {{
                    font-size: 36px;
                    font-weight: 700;
                    margin-bottom: 4px;
                }}
                .stat-label {{
                    font-size: 14px;
                    opacity: 0.9;
                }}
                
                /* Cards */
                .card {{
                    background: var(--bg-card);
                    border-radius: 16px;
                    border: 1px solid var(--border);
                    margin-bottom: 24px;
                    overflow: hidden;
                }}
                .card-header {{
                    padding: 20px 24px;
                    border-bottom: 1px solid var(--border);
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                .card-title {{
                    font-size: 16px;
                    font-weight: 600;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }}
                .card-body {{
                    padding: 24px;
                }}
                
                /* Grid layouts */
                .grid-2 {{
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: 24px;
                }}
                .grid-3 {{
                    display: grid;
                    grid-template-columns: repeat(3, 1fr);
                    gap: 16px;
                }}
                .grid-4 {{
                    display: grid;
                    grid-template-columns: repeat(4, 1fr);
                    gap: 16px;
                }}
                
                /* Forms */
                .form-group {{
                    margin-bottom: 20px;
                }}
                .form-label {{
                    display: block;
                    margin-bottom: 8px;
                    font-size: 13px;
                    font-weight: 500;
                    color: var(--text-muted);
                }}
                .form-input {{
                    width: 100%;
                    padding: 12px 16px;
                    background: var(--bg-input);
                    border: 1px solid var(--border);
                    border-radius: 10px;
                    color: var(--text);
                    font-size: 14px;
                    transition: all 0.2s;
                }}
                .form-input:focus {{
                    outline: none;
                    border-color: var(--primary);
                    box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
                }}
                .form-input::placeholder {{
                    color: var(--text-muted);
                }}
                textarea.form-input {{
                    resize: vertical;
                    min-height: 100px;
                    font-family: 'JetBrains Mono', monospace;
                }}
                .form-hint {{
                    font-size: 12px;
                    color: var(--text-muted);
                    margin-top: 6px;
                }}
                .form-row {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                    gap: 16px;
                    align-items: end;
                }}
                
                /* Buttons */
                .btn {{
                    padding: 12px 24px;
                    border: none;
                    border-radius: 10px;
                    font-size: 14px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.2s;
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                }}
                .btn-primary {{
                    background: var(--primary);
                    color: white;
                }}
                .btn-primary:hover {{
                    background: var(--primary-dark);
                    transform: translateY(-2px);
                }}
                .btn-success {{
                    background: var(--success);
                    color: white;
                }}
                .btn-success:hover {{
                    filter: brightness(1.1);
                }}
                .btn-danger {{
                    background: var(--danger);
                    color: white;
                    padding: 8px 16px;
                    font-size: 13px;
                }}
                .btn-danger:hover {{
                    filter: brightness(1.1);
                }}
                
                /* Tables */
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                th {{
                    text-align: left;
                    padding: 12px 16px;
                    font-size: 12px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    color: var(--text-muted);
                    border-bottom: 1px solid var(--border);
                }}
                td {{
                    padding: 16px;
                    border-bottom: 1px solid var(--border);
                }}
                tr:last-child td {{
                    border-bottom: none;
                }}
                tr:hover {{
                    background: rgba(255,255,255,0.02);
                }}
                
                /* Badges */
                .badge {{
                    display: inline-block;
                    padding: 4px 10px;
                    border-radius: 6px;
                    font-size: 12px;
                    font-weight: 600;
                }}
                .badge-primary {{
                    background: rgba(99, 102, 241, 0.2);
                    color: #a5b4fc;
                }}
                .badge-success {{
                    background: rgba(16, 185, 129, 0.2);
                    color: #6ee7b7;
                }}
                .badge-warning {{
                    background: rgba(245, 158, 11, 0.2);
                    color: #fcd34d;
                }}
                
                /* Code */
                .api-key-code {{
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 12px;
                    background: var(--bg);
                    padding: 6px 10px;
                    border-radius: 6px;
                    color: #a5b4fc;
                }}
                
                /* Model Grid */
                .model-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
                    gap: 12px;
                }}
                .model-card {{
                    background: var(--bg);
                    padding: 16px;
                    border-radius: 12px;
                    border: 1px solid var(--border);
                    transition: all 0.2s;
                }}
                .model-card:hover {{
                    border-color: var(--primary);
                    transform: translateY(-2px);
                }}
                .model-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                    margin-bottom: 8px;
                }}
                .model-name {{
                    font-size: 13px;
                    font-weight: 600;
                    color: var(--text);
                    word-break: break-word;
                }}
                .model-rank {{
                    background: var(--primary);
                    color: white;
                    padding: 2px 8px;
                    border-radius: 10px;
                    font-size: 10px;
                    font-weight: 600;
                    white-space: nowrap;
                }}
                .model-org {{
                    color: var(--text-muted);
                    font-size: 12px;
                }}
                
                /* Slider Styles */
                .slider-container {{
                    display: flex;
                    align-items: center;
                    gap: 16px;
                }}
                .slider {{
                    flex: 1;
                    -webkit-appearance: none;
                    height: 6px;
                    border-radius: 3px;
                    background: var(--bg);
                    outline: none;
                }}
                .slider::-webkit-slider-thumb {{
                    -webkit-appearance: none;
                    width: 20px;
                    height: 20px;
                    border-radius: 50%;
                    background: var(--primary);
                    cursor: pointer;
                    transition: all 0.2s;
                }}
                .slider::-webkit-slider-thumb:hover {{
                    transform: scale(1.2);
                    box-shadow: 0 0 10px var(--primary);
                }}
                .slider-value {{
                    min-width: 70px;
                    text-align: right;
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 14px;
                    color: var(--primary);
                    font-weight: 600;
                }}
                
                /* Section visibility */
                .section {{
                    display: none;
                }}
                .section.active {{
                    display: block;
                }}
                
                /* No data */
                .no-data {{
                    text-align: center;
                    padding: 40px;
                    color: var(--text-muted);
                }}
                
                /* Charts container */
                .chart-container {{
                    position: relative;
                    height: 250px;
                }}
                
                /* Toast notification */
                .toast {{
                    position: fixed;
                    bottom: 24px;
                    right: 24px;
                    background: var(--success);
                    color: white;
                    padding: 16px 24px;
                    border-radius: 12px;
                    font-weight: 500;
                    animation: slideUp 0.3s ease;
                    z-index: 1000;
                }}
                @keyframes slideUp {{
                    from {{ transform: translateY(100px); opacity: 0; }}
                    to {{ transform: translateY(0); opacity: 1; }}
                }}
                
                /* Responsive */
                .mobile-nav-toggle {{
                    display: none;
                    position: fixed;
                    bottom: 20px;
                    right: 20px;
                    z-index: 1001;
                    background: var(--primary);
                    color: white;
                    border: none;
                    border-radius: 50%;
                    width: 56px;
                    height: 56px;
                    font-size: 24px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                    cursor: pointer;
                    align-items: center;
                    justify-content: center;
                }}

                .sidebar-overlay {{
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0,0,0,0.5);
                    z-index: 999;
                    backdrop-filter: blur(2px);
                }}

                @media (max-width: 1024px) {{
                    .layout {{
                        grid-template-columns: 1fr;
                    }}
                    .sidebar {{
                        position: fixed;
                        left: -280px;
                        top: 0;
                        height: 100vh;
                        width: 280px;
                        z-index: 1000;
                        transition: left 0.3s ease;
                        box-shadow: 4px 0 24px rgba(0,0,0,0.5);
                    }}
                    .sidebar.open {{
                        left: 0;
                    }}
                    .sidebar-overlay.open {{
                        display: block;
                    }}
                    .mobile-nav-toggle {{
                        display: flex;
                    }}
                    .main {{
                        padding: 20px;
                    }}
                    .grid-2, .grid-3, .grid-4 {{
                        grid-template-columns: 1fr;
                    }}
                    .stats-grid {{
                        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                        gap: 12px;
                    }}
                    .stat-value {{
                        font-size: 28px;
                    }}
                    
                    /* Table responsiveness */
                    .table-responsive {{
                        overflow-x: auto;
                        -webkit-overflow-scrolling: touch;
                    }}
                    table {{
                        min-width: 600px; /* Force scroll on small screens */
                    }}
                }}
            </style>
            <script>
                function toggleSidebar() {{
                    document.querySelector('.sidebar').classList.toggle('open');
                    document.querySelector('.sidebar-overlay').classList.toggle('open');
                }}
                
                // Close sidebar when clicking a link on mobile
                document.addEventListener('DOMContentLoaded', () => {{
                    const links = document.querySelectorAll('.nav-link');
                    links.forEach(link => {{
                        link.addEventListener('click', () => {{
                            if (window.innerWidth <= 1024) {{
                                toggleSidebar();
                            }}
                        }});
                    }});
                }});
            </script>
        </head>
        <body>
            <div class="sidebar-overlay" onclick="toggleSidebar()"></div>
            <button class="mobile-nav-toggle" onclick="toggleSidebar()">☰</button>
            <div class="layout">
                <!-- Sidebar -->
                <aside class="sidebar">
                    <div class="logo">
                        <span>🚀</span> LMArena Bridge
                    </div>
                    
                    <nav>
                        <div class="nav-section">
                            <div class="nav-label">Dashboard</div>
                            <a class="nav-link active" onclick="showSection('overview')">
                                <span>📊</span> Overview
                            </a>
                        </div>
                        
                        <div class="nav-section">
                            <div class="nav-label">Configuration</div>
                            <a class="nav-link" onclick="showSection('generation')">
                                <span>⚙️</span> Generation Settings
                            </a>
                            <a class="nav-link" onclick="showSection('auth')">
                                <span>🔐</span> Arena Auth
                            </a>
                            <a class="nav-link" onclick="showSection('apikeys')">
                                <span>🔑</span> API Keys
                            </a>
                        </div>
                        
                        <div class="nav-section">
                            <div class="nav-label">Data</div>
                            <a class="nav-link" onclick="showSection('models')">
                                <span>🤖</span> Models
                            </a>
                            <a class="nav-link" onclick="showSection('stats')">
                                <span>📈</span> Statistics
                            </a>
                            <a class="nav-link" onclick="showSection('logs')">
                                <span>📜</span> Live Logs
                            </a>
                        </div>
                        
                        <div class="nav-section">
                            <div class="nav-label">System</div>
                            <a class="nav-link" onclick="showSection('settings')">
                                <span>🛠️</span> Settings
                            </a>
                        </div>
                        
                        <div class="nav-section" style="margin-top: auto; padding-top: 24px; border-top: 1px solid var(--border);">
                            <a href="/logout" class="nav-link">
                                <span>🚪</span> Logout
                            </a>
                        </div>
                    </nav>
                </aside>
                
                <!-- Main Content -->
                <main class="main">
                    <!-- Overview Section -->
                    <div id="section-overview" class="section active">
                        <div class="page-header">
                            <h1 class="page-title">Dashboard Overview</h1>
                            <p class="page-subtitle">Monitor your LMArena Bridge instance</p>
                        </div>
                        
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-value">{get_uptime_string()}</div>
                                <div class="stat-label">⏱️ Server Uptime</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">{sum(model_usage_stats.values())}</div>
                                <div class="stat-label">📊 Total Requests</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">{format_tokens(total_tokens_generated)}</div>
                                <div class="stat-label">🔤 Tokens Generated</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">{len(text_models)}</div>
                                <div class="stat-label">🤖 Available Models</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">{len(auth_tokens)}</div>
                                <div class="stat-label">🔐 Auth Tokens</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">{len(config['api_keys'])}</div>
                                <div class="stat-label">🔑 API Keys</div>
                            </div>
                        </div>
                        
                        <div class="grid-2">
                            <div class="card">
                                <div class="card-header">
                                    <span class="card-title">☁️ Cloudflare Status</span>
                                    <span class="badge {'badge-success' if config.get('cf_clearance') else 'badge-warning'}">{cf_status}</span>
                                </div>
                                <div class="card-body">
                                    <code class="api-key-code" style="display: block; word-break: break-all; padding: 12px;">
                                        {config.get("cf_clearance", "Not set")[:80]}...
                                    </code>
                                    <form action="/refresh-tokens" method="post" style="margin-top: 16px;">
                                        <button type="submit" class="btn btn-success">🔄 Refresh Tokens & Models</button>
                                    </form>
                                </div>
                            </div>
                            
                            <div class="card">
                                <div class="card-header">
                                    <span class="card-title">⚙️ Current Generation Defaults</span>
                                </div>
                                <div class="card-body">
                                    <div class="grid-3">
                                        <div style="text-align: center; padding: 16px; background: var(--bg); border-radius: 12px;">
                                            <div style="font-size: 24px; font-weight: 700; color: var(--primary);">{default_temp}</div>
                                            <div style="font-size: 12px; color: var(--text-muted);">Temperature</div>
                                        </div>
                                        <div style="text-align: center; padding: 16px; background: var(--bg); border-radius: 12px;">
                                            <div style="font-size: 24px; font-weight: 700; color: var(--primary);">{default_top_p}</div>
                                            <div style="font-size: 12px; color: var(--text-muted);">Top P</div>
                                        </div>
                                        <div style="text-align: center; padding: 16px; background: var(--bg); border-radius: 12px;">
                                            <div style="font-size: 24px; font-weight: 700; color: var(--primary);">{default_max_tokens:,}</div>
                                            <div style="font-size: 12px; color: var(--text-muted);">Max Tokens</div>
                                        </div>
                                    </div>
                                    <p style="margin-top: 16px; font-size: 13px; color: var(--text-muted);">
                                        💡 Frontend apps (SillyTavern, etc.) can override these per-request
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Generation Settings Section -->
                    <div id="section-generation" class="section">
                        <div class="page-header">
                            <h1 class="page-title">Generation Settings</h1>
                            <p class="page-subtitle">Configure default parameters for text generation</p>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <span class="card-title">⚙️ Default Parameters</span>
                            </div>
                            <div class="card-body">
                                <form action="/update-generation-settings" method="post">
                                    <div class="form-group">
                                        <label class="form-label">🌡️ Temperature</label>
                                        <div class="slider-container">
                                            <input type="range" class="slider" id="temperature" name="temperature" 
                                                min="0" max="2" step="0.1" value="{default_temp}"
                                                oninput="document.getElementById('temp-value').textContent = this.value">
                                            <span class="slider-value" id="temp-value">{default_temp}</span>
                                        </div>
                                        <p class="form-hint">Controls randomness. Lower = more focused, Higher = more creative (0.0 - 2.0)</p>
                                    </div>
                                    
                                    <div class="form-group">
                                        <label class="form-label">🎯 Top P (Nucleus Sampling)</label>
                                        <div class="slider-container">
                                            <input type="range" class="slider" id="top_p" name="top_p" 
                                                min="0" max="1" step="0.05" value="{default_top_p}"
                                                oninput="document.getElementById('topp-value').textContent = this.value">
                                            <span class="slider-value" id="topp-value">{default_top_p}</span>
                                        </div>
                                        <p class="form-hint">Controls diversity. 1.0 = consider all tokens, 0.1 = consider only top 10% (0.0 - 1.0)</p>
                                    </div>
                                    
                                    <div class="form-group">
                                        <label class="form-label">📝 Max Output Tokens</label>
                                        <input type="number" class="form-input" id="max_tokens" name="max_tokens" 
                                            value="{default_max_tokens}" min="1" max="128000" style="max-width: 300px;">
                                        <p class="form-hint">Maximum tokens to generate. Set high (64000+) for long outputs. Models may have lower limits.</p>
                                    </div>
                                    
                                    <div style="display: flex; gap: 12px; margin-top: 24px;">
                                        <button type="submit" class="btn btn-primary">💾 Save Settings</button>
                                        <button type="button" class="btn" style="background: var(--bg);" 
                                            onclick="resetDefaults()">↩️ Reset to Defaults</button>
                                    </div>
                                </form>
                                
                                <div style="margin-top: 32px; padding: 20px; background: var(--bg); border-radius: 12px; border-left: 4px solid var(--primary);">
                                    <h4 style="margin-bottom: 12px; font-size: 14px;">📌 How It Works</h4>
                                    <ul style="color: var(--text-muted); font-size: 13px; padding-left: 20px;">
                                        <li>These are <strong>default</strong> values used when the frontend doesn't specify them</li>
                                        <li>SillyTavern and other frontends can override these per-request</li>
                                        <li>If your frontend sends temperature=0.9, that will be used instead</li>
                                        <li>Set max_tokens high to allow long outputs (model-dependent)</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Auth Section -->
                    <div id="section-auth" class="section">
                        <div class="page-header">
                            <h1 class="page-title">Arena Authentication</h1>
                            <p class="page-subtitle">Manage your LMArena authentication tokens</p>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <span class="card-title">🔐 Auth Tokens</span>
                                <div style="display: flex; align-items: center; gap: 12px;">
                                    <span class="badge badge-primary">{len(auth_tokens)} Token(s)</span>
                                    <form action="/delete-all-tokens" method="post" style="margin: 0;" onsubmit="return confirm('Are you sure you want to delete ALL auth tokens? This cannot be undone.');">
                                        <button type="submit" class="btn btn-danger" style="padding: 6px 12px; font-size: 12px;">🗑️ Delete All</button>
                                    </form>
                                </div>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table>
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
                                </div>
                                
                                <div style="margin-top: 32px;">
                                    <h4 style="margin-bottom: 16px;">➕ Add Tokens Manually</h4>
                                    <form action="/update-auth-tokens" method="post">
                                        <div class="form-group">
                                            <label class="form-label">Arena Auth Tokens (one per line)</label>
                                            <textarea class="form-input" name="auth_tokens" rows="4" 
                                                placeholder="Paste your arena-auth-prod-v1 tokens here (one per line)"></textarea>
                                            <p class="form-hint">Add multiple tokens to distribute requests and avoid rate limits</p>
                                        </div>
                                        <button type="submit" class="btn btn-primary">Add Tokens</button>
                                    </form>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Auto Collection Card -->
                        <div class="card">
                            <div class="card-header">
                                <span class="card-title">🤖 Auto-Collect Tokens</span>
                                <span class="badge" id="collection-badge" style="background: var(--bg); color: var(--text-muted);">Idle</span>
                            </div>
                            <div class="card-body">
                                <p style="color: var(--text-muted); margin-bottom: 20px;">
                                    Automatically collect authentication tokens using the browser. This will navigate to LMArena, 
                                    capture the auth cookie, clear cookies, and repeat to collect unique tokens.
                                </p>
                                
                                <div class="form-row" style="margin-bottom: 20px;">
                                    <div class="form-group">
                                        <label class="form-label">Tokens to Collect</label>
                                        <input type="number" class="form-input" id="collect-count" value="{config.get('token_collect_count', 15)}" min="1" max="50">
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">Delay Between (seconds)</label>
                                        <input type="number" class="form-input" id="collect-delay" value="{config.get('token_collect_delay', 5)}" min="1" max="60">
                                    </div>
                                </div>
                                
                                <!-- Progress Bar -->
                                <div style="margin-bottom: 20px;">
                                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                                        <span style="font-size: 13px; color: var(--text-muted);">Progress</span>
                                        <span id="progress-text" style="font-size: 13px; color: var(--text-muted);">0 / 0</span>
                                    </div>
                                    <div style="background: var(--bg); height: 8px; border-radius: 4px; overflow: hidden;">
                                        <div id="progress-bar" style="background: var(--primary); height: 100%; width: 0%; transition: width 0.3s;"></div>
                                    </div>
                                </div>
                                
                                <!-- Status -->
                                <div style="background: var(--bg); padding: 12px 16px; border-radius: 8px; margin-bottom: 20px;">
                                    <span style="font-size: 13px; color: var(--text-muted);">Status: </span>
                                    <span id="collection-status" style="font-size: 13px;">Idle</span>
                                </div>
                                
                                <!-- Buttons -->
                                <div style="display: flex; gap: 12px;">
                                    <button id="start-collection-btn" class="btn btn-primary" onclick="startCollection()">
                                        🚀 Start Collection
                                    </button>
                                    <button id="stop-collection-btn" class="btn btn-danger" onclick="stopCollection()" style="display: none;">
                                        ⏹️ Stop Collection
                                    </button>
                                </div>
                                
                                <div style="margin-top: 20px; padding: 16px; background: var(--bg); border-radius: 8px; border-left: 4px solid var(--warning);">
                                    <h4 style="margin-bottom: 8px; font-size: 14px; color: var(--warning);">⚠️ Important Notes</h4>
                                    <ul style="color: var(--text-muted); font-size: 13px; padding-left: 20px; margin: 0;">
                                        <li>This uses the browser instance, so other operations may be paused</li>
                                        <li>Each token requires a page load cycle (~5-10 seconds)</li>
                                        <li>Tokens are saved automatically to your config</li>
                                        <li>Duplicate tokens are automatically skipped</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- API Keys Section -->
                    <div id="section-apikeys" class="section">
                        <div class="page-header">
                            <h1 class="page-title">API Keys</h1>
                            <p class="page-subtitle">Manage access keys for your proxy</p>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <span class="card-title">🔑 Active Keys</span>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table>
                                        <thead>
                                            <tr>
                                                <th>Name</th>
                                                <th>Key</th>
                                                <th>RPM</th>
                                                <th>RPD</th>
                                                <th>Created</th>
                                                <th>Action</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {keys_html if keys_html else '<tr><td colspan="6" class="no-data">No API keys configured</td></tr>'}
                                        </tbody>
                                    </table>
                                </div>
                                
                                <div style="margin-top: 32px;">
                                    <h4 style="margin-bottom: 16px;">➕ Create New API Key</h4>
                                    <form action="/create-key" method="post">
                                        <div class="form-row">
                                            <div class="form-group">
                                                <label class="form-label">Key Name</label>
                                                <input type="text" class="form-input" name="name" placeholder="e.g., Production Key" required>
                                            </div>
                                            <div class="form-group">
                                                <label class="form-label">Rate Limit (RPM)</label>
                                                <input type="number" class="form-input" name="rpm" value="60" min="1" max="1000" required>
                                            </div>
                                            <div class="form-group">
                                                <label class="form-label">Daily Limit (RPD)</label>
                                                <input type="number" class="form-input" name="rpd" value="10000" min="1" required>
                                            </div>
                                            <div class="form-group">
                                                <label class="form-label">&nbsp;</label>
                                                <button type="submit" class="btn btn-primary">Create Key</button>
                                            </div>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Models Section -->
                    <div id="section-models" class="section">
                        <div class="page-header">
                            <h1 class="page-title">Available Models</h1>
                            <p class="page-subtitle">Showing top 20 text-based models (Rank 1 = Best)</p>
                        </div>
                        
                        <div class="card">
                            <div class="card-body">
                                <div class="model-grid">
                                    {models_html}
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Stats Section -->
                    <div id="section-stats" class="section">
                        <div class="page-header">
                            <h1 class="page-title">Usage Statistics</h1>
                            <p class="page-subtitle">Track model usage and request patterns</p>
                        </div>
                        
                        <div class="grid-2">
                            <div class="card">
                                <div class="card-header">
                                    <span class="card-title">📊 Model Distribution</span>
                                </div>
                                <div class="card-body">
                                    <div class="chart-container">
                                        <canvas id="modelPieChart"></canvas>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="card">
                                <div class="card-header">
                                    <span class="card-title">📈 Request Count</span>
                                </div>
                                <div class="card-body">
                                    <div class="chart-container">
                                        <canvas id="modelBarChart"></canvas>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <span class="card-title">📋 Detailed Breakdown</span>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
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
                            </div>
                        </div>
                    </div>
                    
                    <!-- Logs Section -->
                    <div id="section-logs" class="section">
                        <div class="page-header">
                            <h1 class="page-title">Live Logs</h1>
                            <p class="page-subtitle">Real-time server activity and debug output</p>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <span class="card-title">📜 Console Output</span>
                                <div style="display: flex; gap: 8px;">
                                    <button class="btn btn-secondary" onclick="clearLogs()">
                                        🗑️ Clear
                                    </button>
                                    <button class="btn btn-primary" id="autoscroll-btn" onclick="toggleAutoScroll()">
                                        <span id="autoscroll-icon">⏬</span> Auto-scroll
                                    </button>
                                </div>
                            </div>
                            <div class="card-body" style="padding: 0;">
                                <div id="log-container" style="
                                    background: #0d1117;
                                    height: 500px;
                                    overflow-y: auto;
                                    font-family: 'JetBrains Mono', 'Fira Code', monospace;
                                    font-size: 12px;
                                    padding: 16px;
                                    border-radius: 0 0 16px 16px;
                                ">
                                    <div id="log-content"></div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <span class="card-title">🎨 Log Level Colors</span>
                            </div>
                            <div class="card-body">
                                <div style="display: flex; gap: 24px; flex-wrap: wrap;">
                                    <span><span style="color: #58a6ff;">●</span> INFO</span>
                                    <span><span style="color: #3fb950;">●</span> SUCCESS</span>
                                    <span><span style="color: #d29922;">●</span> WARN</span>
                                    <span><span style="color: #f85149;">●</span> ERROR</span>
                                    <span><span style="color: #8b949e;">●</span> DEBUG</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Settings Section -->
                    <div id="section-settings" class="section">
                        <div class="page-header">
                            <h1 class="page-title">Settings</h1>
                            <p class="page-subtitle">Configure system behavior and collection parameters</p>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <span class="card-title">🔄 Token Collection Settings</span>
                            </div>
                            <div class="card-body">
                                <form action="/update-collection-settings" method="post">
                                    <div class="form-row">
                                        <div class="form-group">
                                            <label class="form-label">Default Tokens to Collect</label>
                                            <input type="number" class="form-input" name="token_collect_count" 
                                                value="{config.get('token_collect_count', 15)}" min="1" max="50">
                                            <p class="form-hint">Number of tokens to collect per session (1-50)</p>
                                        </div>
                                        <div class="form-group">
                                            <label class="form-label">Delay Between Collections (seconds)</label>
                                            <input type="number" class="form-input" name="token_collect_delay" 
                                                value="{config.get('token_collect_delay', 5)}" min="1" max="60">
                                            <p class="form-hint">Wait time between each token collection (1-60s)</p>
                                        </div>
                                    </div>
                                    <button type="submit" class="btn btn-primary">💾 Save Settings</button>
                                </form>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <span class="card-title">📊 Current Configuration</span>
                            </div>
                            <div class="card-body">
                                <div style="background: var(--bg); padding: 16px; border-radius: 8px; font-family: monospace; font-size: 13px;">
                                    <div style="margin-bottom: 8px;"><span style="color: var(--text-muted);">DEBUG:</span> <span style="color: var(--primary);">{DEBUG}</span></div>
                                    <div style="margin-bottom: 8px;"><span style="color: var(--text-muted);">PORT:</span> <span style="color: var(--primary);">{PORT}</span></div>
                                    <div style="margin-bottom: 8px;"><span style="color: var(--text-muted);">CHUNK_SIZE:</span> <span style="color: var(--primary);">{CHUNK_SIZE:,}</span></div>
                                    <div style="margin-bottom: 8px;"><span style="color: var(--text-muted);">CHUNK_ROTATION_LIMIT:</span> <span style="color: var(--primary);">{CHUNK_ROTATION_LIMIT}</span></div>
                                    <div style="margin-bottom: 8px;"><span style="color: var(--text-muted);">STICKY_SESSIONS:</span> <span style="color: var(--primary);">{STICKY_SESSIONS}</span></div>
                                    <div><span style="color: var(--text-muted);">RECAPTCHA_CACHE_TTL:</span> <span style="color: var(--primary);">{RECAPTCHA_TOKEN_CACHE_TTL}s</span></div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <span class="card-title">ℹ️ About</span>
                            </div>
                            <div class="card-body">
                                <div style="text-align: center; padding: 20px;">
                                    <div style="font-size: 48px; margin-bottom: 16px;">🚀</div>
                                    <h2 style="margin-bottom: 8px;">LMArena Bridge</h2>
                                    <p style="color: var(--text-muted); margin-bottom: 16px;">High-performance LMArena API proxy</p>
                                    <p style="color: var(--text-muted); font-size: 14px;">
                                        By: <span style="color: var(--primary);">@rumoto</span> and <span style="color: var(--primary);">@norenaboi</span>
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </main>
            </div>
            
            <script>
                // Section navigation
                function showSection(name) {{
                    // Hide all sections
                    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
                    // Show selected section
                    document.getElementById('section-' + name).classList.add('active');
                    // Update nav
                    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                    event.target.closest('.nav-link').classList.add('active');
                }}
                
                // Reset defaults
                function resetDefaults() {{
                    document.getElementById('temperature').value = 0.7;
                    document.getElementById('temp-value').textContent = '0.7';
                    document.getElementById('top_p').value = 1.0;
                    document.getElementById('topp-value').textContent = '1.0';
                    document.getElementById('max_tokens').value = 64000;
                    // Show feedback
                    const btn = event.target;
                    const originalText = btn.textContent;
                    btn.textContent = '✓ Reset!';
                    btn.style.background = 'var(--success)';
                    setTimeout(() => {{
                        btn.textContent = originalText;
                        btn.style.background = 'var(--bg)';
                    }}, 1500);
                }}
                
                // Charts
                const statsData = {json.dumps(dict(sorted(model_usage_stats.items(), key=lambda x: x[1], reverse=True)[:10]))};
                const modelNames = Object.keys(statsData);
                const modelCounts = Object.values(statsData);
                
                const colors = [
                    '#6366f1', '#8b5cf6', '#a855f7', '#d946ef',
                    '#ec4899', '#f43f5e', '#f97316', '#eab308',
                    '#84cc16', '#10b981'
                ];
                
                if (modelNames.length > 0) {{
                    // Pie Chart
                    new Chart(document.getElementById('modelPieChart'), {{
                        type: 'doughnut',
                        data: {{
                            labels: modelNames,
                            datasets: [{{
                                data: modelCounts,
                                backgroundColor: colors,
                                borderWidth: 0
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {{
                                legend: {{
                                    position: 'bottom',
                                    labels: {{ color: '#94a3b8', padding: 12, font: {{ size: 11 }} }}
                                }}
                            }}
                        }}
                    }});
                    
                    // Bar Chart
                    new Chart(document.getElementById('modelBarChart'), {{
                        type: 'bar',
                        data: {{
                            labels: modelNames,
                            datasets: [{{
                                label: 'Requests',
                                data: modelCounts,
                                backgroundColor: colors[0],
                                borderRadius: 6
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {{
                                legend: {{ display: false }}
                            }},
                            scales: {{
                                y: {{
                                    beginAtZero: true,
                                    grid: {{ color: '#334155' }},
                                    ticks: {{ color: '#94a3b8' }}
                                }},
                                x: {{
                                    grid: {{ display: false }},
                                    ticks: {{ color: '#94a3b8', font: {{ size: 10 }}, maxRotation: 45 }}
                                }}
                            }}
                        }}
                    }});
                }}
                
                // Show toast if success param
                if (window.location.search.includes('success')) {{
                    const toast = document.createElement('div');
                    toast.className = 'toast';
                    toast.textContent = '✅ Settings saved successfully!';
                    document.body.appendChild(toast);
                    setTimeout(() => toast.remove(), 3000);
                    history.replaceState(null, '', '/dashboard');
                }}
                
                // === Token Collection Functions ===
                let collectionInterval = null;
                
                async function startCollection() {{
                    const count = document.getElementById('collect-count').value;
                    const delay = document.getElementById('collect-delay').value;
                    
                    const formData = new FormData();
                    formData.append('count', count);
                    formData.append('delay', delay);
                    
                    try {{
                        const response = await fetch('/start-token-collection', {{
                            method: 'POST',
                            body: formData
                        }});
                        const data = await response.json();
                        
                        if (data.error) {{
                            alert(data.error);
                            return;
                        }}
                        
                        document.getElementById('start-collection-btn').style.display = 'none';
                        document.getElementById('stop-collection-btn').style.display = 'inline-flex';
                        
                        // Start polling for status
                        collectionInterval = setInterval(updateCollectionStatus, 1000);
                        updateCollectionStatus();
                    }} catch (e) {{
                        console.error('Error starting collection:', e);
                        alert('Error starting collection');
                    }}
                }}
                
                async function stopCollection() {{
                    try {{
                        await fetch('/stop-token-collection', {{ method: 'POST' }});
                        
                        if (collectionInterval) {{
                            clearInterval(collectionInterval);
                            collectionInterval = null;
                        }}
                        
                        document.getElementById('start-collection-btn').style.display = 'inline-flex';
                        document.getElementById('stop-collection-btn').style.display = 'none';
                    }} catch (e) {{
                        console.error('Error stopping collection:', e);
                    }}
                }}
                
                async function updateCollectionStatus() {{
                    try {{
                        const response = await fetch('/token-collection-status');
                        const data = await response.json();
                        
                        document.getElementById('collection-status').textContent = data.current_status;
                        document.getElementById('progress-text').textContent = `${{data.collected}} / ${{data.target}}`;
                        
                        const percent = data.target > 0 ? (data.collected / data.target) * 100 : 0;
                        document.getElementById('progress-bar').style.width = `${{percent}}%`;
                        
                        const badge = document.getElementById('collection-badge');
                        if (data.running) {{
                            badge.textContent = 'Running...';
                            badge.style.background = 'var(--primary)';
                            badge.style.color = 'white';
                        }} else {{
                            badge.textContent = data.collected > 0 ? `Done (${{data.collected}})` : 'Idle';
                            badge.style.background = data.collected > 0 ? 'var(--success)' : 'var(--bg)';
                            badge.style.color = data.collected > 0 ? 'white' : 'var(--text-muted)';
                            
                            // Stop polling when done
                            if (collectionInterval) {{
                                clearInterval(collectionInterval);
                                collectionInterval = null;
                            }}
                            document.getElementById('start-collection-btn').style.display = 'inline-flex';
                            document.getElementById('stop-collection-btn').style.display = 'none';
                        }}
                    }} catch (e) {{
                        console.error('Error fetching status:', e);
                    }}
                }}
                
                // === Live Logs Functions ===
                let autoScroll = true;
                let logsInterval = null;
                
                function toggleAutoScroll() {{
                    autoScroll = !autoScroll;
                    document.getElementById('autoscroll-icon').textContent = autoScroll ? '⏬' : '⏸️';
                }}
                
                async function fetchLogs() {{
                    try {{
                        const response = await fetch('/api/logs?limit=200');
                        const data = await response.json();
                        
                        if (data.logs) {{
                            const container = document.getElementById('log-content');
                            const levelColors = {{
                                'INFO': '#58a6ff',
                                'SUCCESS': '#3fb950',
                                'WARN': '#d29922',
                                'ERROR': '#f85149',
                                'DEBUG': '#8b949e'
                            }};
                            
                            container.innerHTML = data.logs.map(log => {{
                                const color = levelColors[log.level] || '#8b949e';
                                return `<div style="margin-bottom: 4px;"><span style="color: #6e7681;">${{log.timestamp}}</span> <span style="color: ${{color}};">[${{log.level}}]</span> ${{log.message}}</div>`;
                            }}).join('');
                            
                            if (autoScroll) {{
                                const logContainer = document.getElementById('log-container');
                                logContainer.scrollTop = logContainer.scrollHeight;
                            }}
                        }}
                    }} catch (e) {{
                        console.error('Error fetching logs:', e);
                    }}
                }}
                
                async function clearLogs() {{
                    try {{
                        await fetch('/api/clear-logs', {{ method: 'POST' }});
                        document.getElementById('log-content').innerHTML = '<div style="color: #6e7681;">Logs cleared</div>';
                    }} catch (e) {{
                        console.error('Error clearing logs:', e);
                    }}
                }}
                
                // Start logs polling when on logs section
                function startLogsPolling() {{
                    if (!logsInterval) {{
                        fetchLogs();
                        logsInterval = setInterval(fetchLogs, 2000);
                    }}
                }}
                
                function stopLogsPolling() {{
                    if (logsInterval) {{
                        clearInterval(logsInterval);
                        logsInterval = null;
                    }}
                }}
                
                // Modify showSection to handle logs polling
                const originalShowSection = showSection;
                showSection = function(name) {{
                    // Hide all sections
                    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
                    // Show selected section
                    document.getElementById('section-' + name).classList.add('active');
                    // Update nav
                    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                    event.target.closest('.nav-link').classList.add('active');
                    
                    // Handle logs polling
                    if (name === 'logs') {{
                        startLogsPolling();
                    }} else {{
                        stopLogsPolling();
                    }}
                    
                    // Handle collection status polling
                    if (name === 'auth') {{
                        updateCollectionStatus();
                    }}
                }};
                
                // Initial status check
                updateCollectionStatus();
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

@app.post("/delete-all-tokens")
async def delete_all_tokens(session: str = Depends(get_current_session)):
    if not session:
        return RedirectResponse(url="/login")
    config = get_config()
    token_count = len(config.get("auth_tokens", []))
    config["auth_tokens"] = []
    save_config(config)
    debug_print(f"🗑️ Deleted all {token_count} auth tokens")
    await add_log(f"🗑️ Deleted all {token_count} auth tokens", "WARN")
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

# --- Token Auto-Collection Endpoints ---

@app.post("/start-token-collection")
async def start_token_collection(
    request: Request,
    count: int = Form(15),
    delay: int = Form(5)
):
    """Start automatic token collection in background"""
    session = await get_current_session(request)
    if not session:
        return {"error": "Not authenticated"}
    
    if token_collection_status["running"]:
        return {"error": "Collection already in progress", "status": token_collection_status}
    
    # Update config with new settings
    config = get_config()
    config["token_collect_count"] = count
    config["token_collect_delay"] = delay
    save_config(config)
    
    # Start collection in background
    asyncio.create_task(auto_collect_auth_tokens(count, delay))
    
    return {"success": True, "message": f"Started collecting {count} tokens"}

@app.post("/stop-token-collection")
async def stop_token_collection(request: Request):
    """Stop ongoing token collection"""
    session = await get_current_session(request)
    if not session:
        return {"error": "Not authenticated"}
    
    token_collection_status["running"] = False
    return {"success": True, "message": "Collection stop requested"}

@app.get("/token-collection-status")
async def get_token_collection_status(request: Request):
    """Get current token collection status"""
    session = await get_current_session(request)
    if not session:
        return {"error": "Not authenticated"}
    
    return token_collection_status

# --- Logs Endpoint ---

@app.get("/api/logs")
async def get_logs(request: Request, limit: int = 100):
    """Get recent log entries"""
    session = await get_current_session(request)
    if not session:
        return {"error": "Not authenticated"}
    
    async with log_buffer_lock:
        logs = log_buffer[-limit:] if limit else log_buffer.copy()
    
    return {"logs": logs}

@app.post("/api/clear-logs")
async def clear_logs(request: Request):
    """Clear the log buffer"""
    global log_buffer
    session = await get_current_session(request)
    if not session:
        return {"error": "Not authenticated"}
    
    async with log_buffer_lock:
        log_buffer = []
    
    return {"success": True, "message": "Logs cleared"}

@app.post("/update-collection-settings")
async def update_collection_settings(
    request: Request,
    token_collect_count: int = Form(15),
    token_collect_delay: int = Form(5)
):
    """Update token collection settings"""
    session = await get_current_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=303)
    
    config = get_config()
    config["token_collect_count"] = max(1, min(token_collect_count, 50))  # Clamp 1-50
    config["token_collect_delay"] = max(1, min(token_collect_delay, 60))  # Clamp 1-60s
    save_config(config)
    
    return RedirectResponse(url="/dashboard?success=settings_updated", status_code=303)

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
    models = get_models()
    # Filter for text-based models with an organization (exclude stealth models)
    text_models = [m for m in models 
                   if m.get('capabilities', {}).get('outputCapabilities', {}).get('text')
                   and m.get('organization')]
    
    return {
        "object": "list",
        "data": [
            {
                "id": model.get("publicName"),
                "object": "model",
                "created": int(time.time()),
                "owned_by": "norenaboi"
            } for model in text_models if model.get("publicName")
        ]
    }

async def refresh_recaptcha_token():
    global global_page, cached_recaptcha_token, cached_recaptcha_timestamp
    
    # --- CACHING OPTIMIZATION ---
    # Check if we have a valid cached token (not expired)
    current_time = time.time()
    if cached_recaptcha_token and (current_time - cached_recaptcha_timestamp) < RECAPTCHA_TOKEN_CACHE_TTL:
        age = int(current_time - cached_recaptcha_timestamp)
        print(f"✅ Using cached reCAPTCHA token (age: {age}s / {RECAPTCHA_TOKEN_CACHE_TTL}s TTL)")
        return cached_recaptcha_token
    
    page = global_page
    if not page:
        print("❌ No active page found for reCAPTCHA generation")
        return None
        
    print("🕵️ Extracting fresh reCAPTCHA token (cache expired or empty)...")
    try:
        # We need to find the site key first. It's usually in the HTML.
        # Look for 'grecaptcha.execute("SITE_KEY"' or similar
        # Or just try to execute grecaptcha if it's loaded
        
        # 1. Check if grecaptcha is defined (wait for it)
        is_grecaptcha = False
        print("   Waiting for grecaptcha to load...")
        for i in range(20):
            is_grecaptcha = await page.evaluate("typeof grecaptcha !== 'undefined' || typeof window.grecaptcha !== 'undefined'")
            if is_grecaptcha:
                break
            await asyncio.sleep(1)
        
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
                    # Update both config AND cache
                    config = get_config()
                    config["recaptcha_token"] = token
                    save_config(config)
                    # Update cache for fast subsequent requests
                    cached_recaptcha_token = token
                    cached_recaptcha_timestamp = time.time()
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
                
                # 4. Wait for the token to appear in the input
                print("   Waiting for token in hidden input...")
                token = None
                for _ in range(60): # Wait up to 60 seconds
                    token = await page.evaluate("document.getElementById('recaptcha-token-output').value")
                    if token:
                        break
                    await asyncio.sleep(1)
                
                if token and not token.startswith("ERROR"):
                    print(f"✅ Generated reCAPTCHA token via DOM bridge: {token[:20]}...")
                    # Update both config AND cache
                    config = get_config()
                    config["recaptcha_token"] = token
                    save_config(config)
                    # Update cache for fast subsequent requests
                    cached_recaptcha_token = token
                    cached_recaptcha_timestamp = time.time()
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

# --- Full-Page Cloudflare Challenge Handler ---
async def handle_cloudflare_challenge(page, context: str = "unknown", max_wait: int = 30) -> bool:
    """
    Handle full-page Cloudflare challenge (the "Just a moment..." interstitial page).
    This is different from in-page Turnstile modals - it's the main Cloudflare protection
    that appears before you even reach the website.
    
    Args:
        page: Playwright page object
        context: String describing when this is being called (for logging)
        max_wait: Maximum seconds to wait for challenge to complete
    
    Returns:
        True if challenge was passed, False otherwise
    """
    await add_log(f"🛡️ [{context}] Checking for full-page Cloudflare challenge...", "INFO")
    
    # Check page title to see if we're on Cloudflare challenge page
    current_title = await page.title()
    if "Just a moment" not in current_title and "Cloudflare" not in current_title:
        await add_log(f"✅ [{context}] Not on Cloudflare challenge page (title: {current_title[:50]}...)", "DEBUG")
        return True  # Already past the challenge
    
    await add_log(f"🛡️ [{context}] Cloudflare challenge detected! Title: '{current_title}'", "WARN")
    
    # Random mouse movements to appear human
    await add_log(f"🖱️ [{context}] Performing human-like mouse movements...", "DEBUG")
    try:
        await page.mouse.move(random.randint(100, 400), random.randint(100, 400))
        await asyncio.sleep(0.3 + random.random() * 0.3)
        await page.mouse.move(random.randint(100, 500), random.randint(100, 400), steps=random.randint(8, 15))
        await asyncio.sleep(0.2 + random.random() * 0.3)
    except Exception as e:
        await add_log(f"⚠️ [{context}] Mouse movement error (continuing): {e}", "DEBUG")
    
    # Look for Turnstile iframe in page frames
    await add_log(f"🔍 [{context}] Scanning page frames for Turnstile iframe...", "INFO")
    
    turnstile_frame = None
    for poll_attempt in range(15):  # Poll for up to 15 seconds
        for frame in page.frames:
            if "challenges.cloudflare.com" in frame.url and "turnstile" in frame.url:
                turnstile_frame = frame
                await add_log(f"✅ [{context}] Found Turnstile frame: {frame.url[:80]}...", "SUCCESS")
                break
        if turnstile_frame:
            break
        await asyncio.sleep(1)
        if poll_attempt % 3 == 0:
            await add_log(f"🔍 [{context}] Still searching for Turnstile frame... (attempt {poll_attempt + 1}/15)", "DEBUG")
    
    if not turnstile_frame:
        await add_log(f"⚠️ [{context}] No Turnstile iframe found - checking if challenge auto-solved...", "WARN")
        await asyncio.sleep(3)
        current_title = await page.title()
        if "Just a moment" not in current_title:
            await add_log(f"✅ [{context}] Challenge appears to have auto-solved! Title: {current_title[:50]}", "SUCCESS")
            return True
        await add_log(f"❌ [{context}] Could not find Turnstile and challenge not solved", "ERROR")
        return False
    
    # Wait for Turnstile content to render
    await add_log(f"⏳ [{context}] Waiting for Turnstile content to render...", "DEBUG")
    await asyncio.sleep(random.uniform(2.0, 3.5))
    
    # Debug: Print frame content preview
    try:
        frame_content = await turnstile_frame.content()
        await add_log(f"🔍 [{context}] Frame content preview: {frame_content[:200]}...", "DEBUG")
    except Exception as e:
        await add_log(f"⚠️ [{context}] Could not read frame content: {e}", "DEBUG")
    
    # Try multiple methods to click the Turnstile checkbox
    clicked = False
    
    # Method 1: Try to find and click checkbox input directly in frame
    await add_log(f"🖱️ [{context}] Method 1: Searching for checkbox in Turnstile frame...", "DEBUG")
    checkbox_selectors = [
        'input[type="checkbox"]',
        '.cb-lb',
        'label',
        '.ctp-checkbox-label',
        '#challenge-stage',
        '.big-button',
        '[data-testid="checkbox"]'
    ]
    
    for sel in checkbox_selectors:
        try:
            checkbox = await turnstile_frame.query_selector(sel)
            if checkbox:
                await add_log(f"✅ [{context}] Found checkbox with selector: {sel}", "SUCCESS")
                cb_box = await checkbox.bounding_box()
                if cb_box:
                    x = cb_box['x'] + cb_box['width'] / 2
                    y = cb_box['y'] + cb_box['height'] / 2
                    await add_log(f"🖱️ [{context}] Moving to checkbox at ({int(x)}, {int(y)})...", "DEBUG")
                    await page.mouse.move(x, y, steps=random.randint(12, 20))
                    await asyncio.sleep(random.uniform(0.2, 0.5))
                    await page.mouse.down()
                    await asyncio.sleep(random.uniform(0.05, 0.15))
                    await page.mouse.up()
                    await add_log(f"✅ [{context}] Clicked checkbox element!", "SUCCESS")
                    clicked = True
                    break
                else:
                    await checkbox.click()
                    await add_log(f"✅ [{context}] Clicked checkbox (no bounding box, direct click)", "SUCCESS")
                    clicked = True
                    break
        except Exception as e:
            continue
    
    # Method 2: Click at checkbox position within iframe bounding box
    if not clicked:
        await add_log(f"🖱️ [{context}] Method 2: Clicking at checkbox position in iframe...", "DEBUG")
        try:
            iframes = await page.query_selector_all('iframe')
            for iframe_el in iframes:
                src = await iframe_el.get_attribute('src') or ""
                if "challenges.cloudflare.com" in src or "turnstile" in src.lower():
                    box = await iframe_el.bounding_box()
                    if box:
                        # Checkbox is at left side of iframe, about 28px in
                        cx = box['x'] + 28
                        cy = box['y'] + box['height'] / 2
                        
                        await add_log(f"📐 [{context}] Turnstile iframe bounds: x={int(box['x'])}, y={int(box['y'])}, w={int(box['width'])}, h={int(box['height'])}", "DEBUG")
                        await add_log(f"🖱️ [{context}] Clicking checkbox position at ({int(cx)}, {int(cy)})...", "INFO")
                        
                        await page.mouse.move(cx, cy, steps=random.randint(10, 18))
                        await asyncio.sleep(random.uniform(0.2, 0.4))
                        await page.mouse.click(cx, cy)
                        await add_log(f"✅ [{context}] Clicked Turnstile checkbox position!", "SUCCESS")
                        clicked = True
                        break
        except Exception as e:
            await add_log(f"⚠️ [{context}] Iframe checkbox click failed: {e}", "WARN")
    
    # Method 3: Click frame body as fallback
    if not clicked:
        await add_log(f"🖱️ [{context}] Method 3: Clicking frame body at checkbox position...", "DEBUG")
        try:
            body = await turnstile_frame.query_selector('body')
            if body:
                box = await body.bounding_box()
                if box:
                    cx = box['x'] + 28
                    cy = box['y'] + box['height'] / 2
                    await page.mouse.click(cx, cy)
                    await add_log(f"✅ [{context}] Clicked frame body at ({int(cx)}, {int(cy)})", "SUCCESS")
                    clicked = True
        except Exception as e:
            await add_log(f"⚠️ [{context}] Frame body click failed: {e}", "WARN")
    
    if not clicked:
        await add_log(f"❌ [{context}] All click methods failed", "ERROR")
        return False
    
    # Wait for challenge to complete
    await add_log(f"⏳ [{context}] Waiting for Cloudflare challenge to complete (max {max_wait}s)...", "INFO")
    
    for wait_second in range(max_wait):
        await asyncio.sleep(1)
        
        try:
            current_title = await page.title()
            if "Just a moment" not in current_title and "Cloudflare" not in current_title:
                await add_log(f"✅ [{context}] Cloudflare challenge PASSED! Title: '{current_title[:50]}'", "SUCCESS")
                await asyncio.sleep(1)  # Let page stabilize
                return True
            
            if wait_second % 5 == 4:
                await add_log(f"⏳ [{context}] Still waiting... ({wait_second + 1}/{max_wait}s) Title: '{current_title}'", "DEBUG")
        except Exception as e:
            await add_log(f"⚠️ [{context}] Error checking title: {e}", "DEBUG")
    
    # Final check
    try:
        final_title = await page.title()
        if "Just a moment" not in final_title:
            await add_log(f"✅ [{context}] Challenge passed in final check! Title: '{final_title[:50]}'", "SUCCESS")
            return True
    except:
        pass
    
    await add_log(f"❌ [{context}] Cloudflare challenge NOT passed after {max_wait}s", "ERROR")
    return False


# --- Reusable Turnstile Handler ---
async def handle_turnstile_modal(page, context: str = "unknown") -> bool:
    """
    Handle Cloudflare Turnstile modal (Security Verification dialog).
    This can appear at various points: after page load, after sending message, etc.
    
    Args:
        page: Playwright page object
        context: String describing when this is being called (for logging)
    
    Returns:
        True if Turnstile was found and handled, False otherwise
    """
    await add_log(f"🔍 [{context}] Checking for Turnstile/Security Verification...", "DEBUG")
    
    # Check if any Turnstile-related modal is present
    turnstile_present = await page.evaluate("""
        () => {
            // Method 1: Check for Security Verification text in dialogs
            const dialogs = document.querySelectorAll('[role="dialog"]');
            for (const dialog of dialogs) {
                const text = dialog.textContent || '';
                if (text.includes('Security Verification') || text.includes('Verify you are human')) {
                    return { found: true, type: 'security_dialog' };
                }
            }
            
            // Method 2: Check for Turnstile iframe anywhere on page
            const iframes = document.querySelectorAll('iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"]');
            for (const iframe of iframes) {
                const rect = iframe.getBoundingClientRect();
                if (rect.width > 0 && rect.height > 0) {
                    return { found: true, type: 'turnstile_iframe', x: rect.x + 35, y: rect.y + rect.height / 2 };
                }
            }
            
            // Method 3: Check for "Verify you are human" checkbox container
            const verifyContainers = document.querySelectorAll('[class*="turnstile"], [id*="turnstile"], [class*="cf-"]');
            for (const container of verifyContainers) {
                const rect = container.getBoundingClientRect();
                if (rect.width > 0 && rect.height > 0) {
                    return { found: true, type: 'turnstile_container', x: rect.x + 30, y: rect.y + rect.height / 2 };
                }
            }
            
            return { found: false };
        }
    """)
    
    if not turnstile_present.get('found'):
        await add_log(f"✅ [{context}] No Turnstile detected", "DEBUG")
        return False
    
    await add_log(f"🛡️ [{context}] Turnstile detected (type: {turnstile_present.get('type')})!", "INFO")
    
    # Try multiple methods to click the Turnstile checkbox
    clicked = False
    
    for attempt in range(5):  # 5 attempts
        if clicked:
            break
        await add_log(f"🛡️ [{context}] Click attempt {attempt + 1}/5...", "DEBUG")
        
        # Method 1: Click via bounding box from JS evaluation
        if not clicked and turnstile_present.get('x') and turnstile_present.get('y'):
            try:
                x, y = turnstile_present['x'], turnstile_present['y']
                await page.mouse.move(x, y, steps=5)
                await asyncio.sleep(0.2)
                await page.mouse.click(x, y)
                await add_log(f"✅ [{context}] Clicked at ({int(x)}, {int(y)}) via bounding box!", "SUCCESS")
                clicked = True
            except Exception as e:
                await add_log(f"⚠️ [{context}] Bounding box click failed: {e}", "DEBUG")
        
        # Method 2: Re-evaluate to get fresh coordinates
        if not clicked:
            try:
                fresh_info = await page.evaluate("""
                    () => {
                        const iframes = document.querySelectorAll('iframe[src*="challenges.cloudflare.com"]');
                        for (const iframe of iframes) {
                            const rect = iframe.getBoundingClientRect();
                            if (rect.width > 0 && rect.height > 0) {
                                return { found: true, x: rect.x + 35, y: rect.y + rect.height / 2 };
                            }
                        }
                        return { found: false };
                    }
                """)
                if fresh_info.get('found'):
                    x, y = fresh_info['x'], fresh_info['y']
                    await page.mouse.move(x, y, steps=5)
                    await asyncio.sleep(0.2)
                    await page.mouse.click(x, y)
                    await add_log(f"✅ [{context}] Clicked at ({int(x)}, {int(y)}) via fresh evaluation!", "SUCCESS")
                    clicked = True
            except Exception as e:
                await add_log(f"⚠️ [{context}] Fresh evaluation click failed: {e}", "DEBUG")
        
        # Method 3: Access Turnstile frame directly
        if not clicked:
            try:
                for frame in page.frames:
                    if 'challenges.cloudflare.com' in frame.url:
                        await add_log(f"🛡️ [{context}] Found Turnstile frame: {frame.url[:60]}...", "DEBUG")
                        
                        # Try clicking checkbox input
                        checkbox = await frame.query_selector('input[type="checkbox"]')
                        if checkbox:
                            await checkbox.click()
                            await add_log(f"✅ [{context}] Clicked checkbox in frame!", "SUCCESS")
                            clicked = True
                            break
                        
                        # Try clicking body
                        body = await frame.query_selector('body')
                        if body:
                            box = await body.bounding_box()
                            if box:
                                click_x = box['x'] + 30
                                click_y = box['y'] + box['height'] / 2
                                await page.mouse.click(click_x, click_y)
                                await add_log(f"✅ [{context}] Clicked frame body at ({int(click_x)}, {int(click_y)})!", "SUCCESS")
                                clicked = True
                                break
            except Exception as e:
                await add_log(f"⚠️ [{context}] Frame access failed: {e}", "DEBUG")
        
        if not clicked:
            await asyncio.sleep(1)
    
    if not clicked:
        await add_log(f"⚠️ [{context}] Could not click Turnstile after 5 attempts", "WARN")
        return False
    
    # Wait for Turnstile verification to complete
    await add_log(f"⏳ [{context}] Waiting for Turnstile verification...", "DEBUG")
    
    for wait_attempt in range(15):  # Wait up to 15 seconds
        await asyncio.sleep(1)
        
        # Check if Turnstile is gone
        still_present = await page.evaluate("""
            () => {
                // Check dialogs
                const dialogs = document.querySelectorAll('[role="dialog"]');
                for (const dialog of dialogs) {
                    const text = dialog.textContent || '';
                    if (text.includes('Security Verification') || text.includes('Verify you are human')) {
                        return true;
                    }
                }
                
                // Check iframes - but only visible ones
                const iframes = document.querySelectorAll('iframe[src*="challenges.cloudflare.com"]');
                for (const iframe of iframes) {
                    const rect = iframe.getBoundingClientRect();
                    // Only count if visible (not just present in DOM)
                    if (rect.width > 50 && rect.height > 50) {
                        return true;
                    }
                }
                
                return false;
            }
        """)
        
        if not still_present:
            await add_log(f"✅ [{context}] Turnstile verification completed!", "SUCCESS")
            await asyncio.sleep(0.5)  # Brief stabilization
            return True
        
        if wait_attempt == 14:
            await add_log(f"⚠️ [{context}] Turnstile still visible after 15s", "WARN")
    
    return clicked


# --- Auto Token Collection ---
async def auto_collect_auth_tokens(count: int = 15, delay: int = 5):
    """
    Automatically collect arena-auth-prod-v1 tokens using the GLOBAL browser.
    This reuses the browser that already passed Cloudflare challenge.
    """
    global global_page, global_browser, token_collection_status
    
    token_collection_status["running"] = True
    token_collection_status["collected"] = 0
    token_collection_status["target"] = count
    token_collection_status["current_status"] = "Starting..."
    token_collection_status["errors"] = []
    
    collected_tokens = []
    config = get_config()
    existing_tokens = set(config.get("auth_tokens", []))
    
    await add_log(f"🚀 Starting auto-collection of {count} tokens...", "INFO")
    
    # Use the GLOBAL browser that already passed Cloudflare!
    # Creating a new browser instance triggers fresh Cloudflare challenges
    collection_context = None
    collection_page = None
    
    try:
        # Check if global browser is available
        if global_browser is None:
            await add_log("⚠️ Global browser not initialized. Running initial data retrieval first...", "WARN")
            token_collection_status["current_status"] = "Initializing browser..."
            await get_initial_data()
            
            if global_browser is None:
                await add_log("❌ Failed to initialize browser", "ERROR")
                token_collection_status["current_status"] = "❌ Browser initialization failed"
                token_collection_status["running"] = False
                return []
        
        await add_log("🌐 Using global browser (already passed Cloudflare)...", "INFO")
        token_collection_status["current_status"] = "Creating collection context..."
        
        # Create a NEW CONTEXT in the existing browser
        # This shares the browser's Cloudflare clearance but has separate cookies
        collection_context = await global_browser.new_context(
            ignore_https_errors=True,
        )
        collection_page = await collection_context.new_page()
        
        # Browser console logs disabled (too noisy - enable for debugging if needed)
        # collection_page.on("console", lambda msg: print(f"[Browser Console] {msg.text}"))
        
        await add_log("✅ Collection context ready", "SUCCESS")
        
        # Track if we've found the auth token
        found_auth_token = {"value": None}
        
        # Listen for responses that might set the auth token cookie
        async def on_response(response):
            try:
                url = response.url
                
                # Log interesting API calls
                if '/api/' in url or '/chat' in url or 'queue' in url:
                    await add_log(f"🔗 API Response: {response.status} {url[:80]}...", "DEBUG")
                
                # Check ALL response headers for auth cookie
                all_headers = await response.all_headers()
                
                # Check for Set-Cookie in various forms (headers can be case-insensitive)
                for header_name, header_value in all_headers.items():
                    if header_name.lower() == 'set-cookie':
                        if 'arena-auth-prod-v1' in header_value:
                            # Extract the token value
                            import re
                            match = re.search(r'arena-auth-prod-v1=([^;]+)', header_value)
                            if match:
                                token = match.group(1)
                                found_auth_token["value"] = token
                                await add_log(f"🎯 AUTH TOKEN FOUND in response from {url}!", "SUCCESS")
                                await add_log(f"🔑 Token: {token[:50]}...", "SUCCESS")
            except Exception as e:
                pass
        
        # Ensure the listener is attached
        collection_page.on("response", on_response)
        await add_log("👂 Response listener attached", "DEBUG")
        
        # --- Apply same stealth techniques as main browser ---
        # 1. Randomize Viewport (Desktop sizes)
        width = random.randint(1366, 1920)
        height = random.randint(768, 1080)
        await collection_page.set_viewport_size({"width": width, "height": height})
        
        # 2. Set Realistic Headers
        await collection_page.set_extra_http_headers({
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-User": "?1"
        })
        
        # 3. Remove webdriver property & Add cookie/storage monitor
        await collection_page.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
            
            // Monitor for auth token in cookies
            setInterval(() => {
                if (document.cookie.includes('arena-auth-prod-v1')) {
                    console.log('🍪 JS DETECTED AUTH COOKIE IN DOCUMENT.COOKIE!');
                }
            }, 1000);
            
            // Monitor localStorage
            const originalSetItem = localStorage.setItem.bind(localStorage);
            localStorage.setItem = function(key, value) {
                if (key.includes('auth') || key.includes('token') || key.includes('arena')) {
                    console.log('📦 localStorage SET:', key, '=', value.substring(0, 100));
                }
                return originalSetItem(key, value);
            };
            
            // Monitor sessionStorage
            const originalSessionSetItem = sessionStorage.setItem.bind(sessionStorage);
            sessionStorage.setItem = function(key, value) {
                if (key.includes('auth') || key.includes('token') || key.includes('arena')) {
                    console.log('📦 sessionStorage SET:', key, '=', value.substring(0, 100));
                }
                return originalSessionSetItem(key, value);
            };
        """)
        
        await add_log("✅ Collection browser ready (headless + stealth)", "SUCCESS")
        
        for i in range(count):
            if not token_collection_status["running"]:
                await add_log("⏹️ Collection stopped by user", "WARN")
                break
                
            token_collection_status["current_status"] = f"Collecting token {i + 1}/{count}..."
            await add_log(f"🔄 Collecting token {i + 1}/{count}...", "INFO")
            
            # Reset the found token tracker for this iteration
            found_auth_token["value"] = None
            
            try:
                # Clear cookies before navigation to get fresh token
                await collection_context.clear_cookies()
                
                # Navigate to LMArena - using the global browser that already passed Cloudflare
                await add_log(f"🌐 Navigating to LMArena...", "DEBUG")
                await collection_page.goto(
                    "https://lmarena.ai/?mode=direct", 
                    wait_until="domcontentloaded",
                    timeout=60000
                )
                
                # Wait for page to load
                await asyncio.sleep(3)
                
                # Check page state
                current_title = await collection_page.title()
                await add_log(f"📄 Page title: {current_title}", "DEBUG")
                
                # If still on Cloudflare, use the full-page challenge handler
                if "Just a moment" in current_title or "Cloudflare" in current_title:
                    await add_log("⚠️ Cloudflare challenge detected in collection context!", "WARN")
                    
                    # Use the comprehensive full-page Cloudflare handler
                    challenge_passed = await handle_cloudflare_challenge(collection_page, "collection", max_wait=25)
                    
                    if not challenge_passed:
                        await add_log("❌ Could not pass Cloudflare challenge - skipping this attempt", "ERROR")
                        token_collection_status["errors"].append(f"Cloudflare challenge failed on attempt {i + 1}")
                        continue
                    
                    await add_log("✅ Cloudflare challenge passed!", "SUCCESS")
                    # Additional stabilization wait after passing challenge
                    await asyncio.sleep(2)
                
                # Page should be loaded now - try to trigger auth token generation
                token_collection_status["current_status"] = f"Triggering auth ({i + 1}/{count})..."
                
                # Check for Turnstile modal that may appear on page load
                await handle_turnstile_modal(collection_page, "pre_interaction")

                # --- Streamlined Interaction to Trigger Auth ---
                token_collection_status["current_status"] = f"Triggering auth ({i + 1}/{count})..."
                
                try:
                    # ============================================================
                    # STEP 1: SELECT A MODEL FIRST (Required for Direct Chat mode)
                    # In Direct Chat mode, you MUST select a model before sending
                    # messages, otherwise the send will fail with "undefined"
                    # ============================================================
                    await add_log("🎯 Step 1: Selecting a model...", "DEBUG")
                    
                    model_selected = False
                    try:
                        # Look for model selector dropdown/button
                        model_selector_btn = await collection_page.query_selector(
                            'button[aria-haspopup="listbox"], '
                            'button:has-text("Select a model"), '
                            '[data-testid="model-selector"], '
                            '.model-selector'
                        )
                        
                        if model_selector_btn:
                            await add_log("📋 Found model selector button, clicking...", "DEBUG")
                            await model_selector_btn.click(timeout=3000)
                            await asyncio.sleep(1)
                            
                            # Look for a model option to click (pick first available model)
                            model_option = await collection_page.query_selector(
                                '[role="option"], '
                                '[role="listbox"] button, '
                                '[data-testid*="model-option"], '
                                '.model-option'
                            )
                            
                            if model_option:
                                await add_log("✅ Found model option, selecting...", "DEBUG")
                                await model_option.click(timeout=3000)
                                model_selected = True
                                await asyncio.sleep(1)
                            else:
                                # Try clicking using JS to find any model in the dropdown
                                model_selected = await collection_page.evaluate("""
                                    () => {
                                        // Look for model options in listbox
                                        const options = document.querySelectorAll('[role="option"], [role="listbox"] button');
                                        if (options.length > 0) {
                                            options[0].click();
                                            return true;
                                        }
                                        // Try finding by text content
                                        const buttons = document.querySelectorAll('button');
                                        for (const btn of buttons) {
                                            if (btn.textContent.includes('gpt') || 
                                                btn.textContent.includes('claude') || 
                                                btn.textContent.includes('gemini') ||
                                                btn.textContent.includes('llama')) {
                                                btn.click();
                                                return true;
                                            }
                                        }
                                        return false;
                                    }
                                """)
                                if model_selected:
                                    await add_log("✅ Selected model via JS", "DEBUG")
                                    await asyncio.sleep(1)
                        else:
                            # Try alternative: Click directly on model name if visible
                            await add_log("⚠️ Model selector button not found, trying alternatives...", "DEBUG")
                            model_selected = await collection_page.evaluate("""
                                () => {
                                    // Some pages show model names directly
                                    const modelLinks = document.querySelectorAll('a[href*="model"], button[data-model]');
                                    if (modelLinks.length > 0) {
                                        modelLinks[0].click();
                                        return true;
                                    }
                                    return false;
                                }
                            """)
                    except Exception as model_err:
                        await add_log(f"⚠️ Model selection error: {model_err}", "DEBUG")
                    
                    if not model_selected:
                        await add_log("⚠️ Could not select model, proceeding anyway (may fail)", "WARN")
                    else:
                        await add_log("✅ Model selected!", "SUCCESS")
                    
                    # ============================================================
                    # STEP 2: Wait for reCAPTCHA to be ready
                    # The page loads Google reCAPTCHA which needs to initialize
                    # ============================================================
                    await add_log("🔐 Waiting for reCAPTCHA to initialize...", "DEBUG")
                    await asyncio.sleep(2)
                    
                    # ============================================================
                    # STEP 3: Find and interact with the chat textarea
                    # ============================================================
                    # Try to find and interact with the chat textarea
                    chat_selectors = [
                        'textarea[placeholder*="message"]',
                        'textarea[placeholder*="Send"]',
                        'textarea[placeholder*="Ask"]',
                        'textarea',
                        '[role="textbox"]',
                    ]
                    
                    textarea_found = False
                    for selector in chat_selectors:
                        try:
                            element = await collection_page.query_selector(selector)
                            if element:
                                await add_log(f"📝 Found chat input: {selector}", "DEBUG")
                                
                                # Click the textarea
                                try:
                                    await element.click(timeout=2000)
                                except Exception:
                                    await collection_page.evaluate("(el) => el.click()", element)
                                
                                # CHECK: Skip sending message if auth token already found
                                if found_auth_token["value"]:
                                    await add_log("⚡ Auth token already found, skipping message send!", "SUCCESS")
                                    textarea_found = True
                                    break
                                
                                # Type "Hello!" and send
                                await add_log("💬 Sending test message 'Hello!'...", "DEBUG")
                                await element.type("Hello!", delay=50)
                                await asyncio.sleep(0.3)
                                await collection_page.keyboard.press("Enter")
                                
                                # Brief wait for dialogs to appear
                                await asyncio.sleep(2)
                                
                                # ============================================================
                                # DIALOG HANDLING LOOP
                                # The order of dialogs can vary, and Turnstile can appear
                                # ON TOP OF Terms dialog. We need to handle Turnstile first
                                # whenever it appears, then handle Terms.
                                # ============================================================
                                
                                # Loop to handle dialogs - Turnstile can appear multiple times
                                for dialog_round in range(5):  # Max 5 rounds of dialog handling
                                    # CHECK: Skip dialog handling if auth token already found
                                    if found_auth_token["value"]:
                                        await add_log("⚡ Auth token found, skipping remaining dialog handling!", "SUCCESS")
                                        break
                                    
                                    await add_log(f"🔄 Dialog handling round {dialog_round + 1}/5...", "DEBUG")
                                    
                                    # ALWAYS check for Turnstile first (it appears ON TOP of other dialogs)
                                    turnstile_handled = await handle_turnstile_modal(collection_page, f"round_{dialog_round + 1}")
                                    
                                    if turnstile_handled:
                                        # Turnstile was handled, check for more dialogs
                                        await asyncio.sleep(1)
                                        continue  # Go back to check for more Turnstile/dialogs
                                    
                                    # No Turnstile found, check for Terms of Use dialog
                                    terms_present = await collection_page.evaluate("""
                                        () => {
                                            const dialogs = document.querySelectorAll('[role="dialog"]');
                                            for (const dialog of dialogs) {
                                                const text = dialog.textContent || '';
                                                if (text.includes('Terms of Use') || text.includes('Privacy Policy')) {
                                                    return true;
                                                }
                                            }
                                            const buttons = document.querySelectorAll('button');
                                            for (const btn of buttons) {
                                                if (btn.textContent.trim() === 'Agree') {
                                                    return true;
                                                }
                                            }
                                            return false;
                                        }
                                    """)
                                    
                                    if terms_present:
                                        await add_log("📜 Terms of Use dialog detected!", "INFO")
                                        
                                        # ============================================================
                                        # NEW APPROACH: Set localStorage directly to bypass Terms
                                        # The Terms dialog checks localStorage for acceptance.
                                        # We'll set the flag directly AND dismiss the dialog.
                                        # ============================================================
                                        await add_log("📜 Setting Terms acceptance directly via localStorage...", "DEBUG")
                                        
                                        try:
                                            # Set ALL possible Terms-related localStorage keys
                                            # LMArena uses various key patterns
                                            await collection_page.evaluate("""
                                                () => {
                                                    // Common patterns for Terms acceptance in React apps
                                                    const keysToSet = [
                                                        'terms_accepted',
                                                        'termsAccepted', 
                                                        'tos_accepted',
                                                        'tosAccepted',
                                                        'lmarena_terms_accepted',
                                                        'lmarena_tos',
                                                        'arena_terms',
                                                        'user_accepted_terms',
                                                        'agreed_to_terms',
                                                        'privacy_policy_accepted',
                                                        'hasAcceptedTerms',
                                                        'terms-of-use-accepted'
                                                    ];
                                                    
                                                    for (const key of keysToSet) {
                                                        localStorage.setItem(key, 'true');
                                                        localStorage.setItem(key, '1');
                                                        sessionStorage.setItem(key, 'true');
                                                    }
                                                    
                                                    // Also try to find and log existing localStorage keys
                                                    console.log('📦 localStorage keys:', Object.keys(localStorage));
                                                }
                                            """)
                                            await add_log("✅ localStorage Terms flags set", "SUCCESS")
                                        except Exception as e:
                                            await add_log(f"⚠️ localStorage set failed: {e}", "DEBUG")
                                        
                                        # Before clicking Agree, check for Turnstile one more time
                                        # (it can appear ON TOP of Terms)
                                        await handle_turnstile_modal(collection_page, "pre_terms")
                                        await asyncio.sleep(0.5)
                                        
                                        # Check if there's a Turnstile INSIDE the Terms dialog itself
                                        # This is common - the Agree button won't work until the embedded Turnstile is solved
                                        try:
                                            terms_turnstile = await collection_page.evaluate("""
                                                () => {
                                                    const dialogs = document.querySelectorAll('[role="dialog"]');
                                                    for (const dialog of dialogs) {
                                                        if (dialog.textContent.includes('Terms of Use')) {
                                                            // Look for Turnstile iframe within the dialog
                                                            const iframe = dialog.querySelector('iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"]');
                                                            if (iframe) {
                                                                const rect = iframe.getBoundingClientRect();
                                                                if (rect.width > 0 && rect.height > 0) {
                                                                    return { found: true, x: rect.x + 30, y: rect.y + rect.height / 2 };
                                                                }
                                                            }
                                                            
                                                            // Also look for any clickable verification area
                                                            const turnstileDiv = dialog.querySelector('[class*="turnstile"], [id*="turnstile"], [class*="cf-"]');
                                                            if (turnstileDiv) {
                                                                const rect = turnstileDiv.getBoundingClientRect();
                                                                if (rect.width > 0 && rect.height > 0) {
                                                                    return { found: true, x: rect.x + 30, y: rect.y + rect.height / 2 };
                                                                }
                                                            }
                                                        }
                                                    }
                                                    return { found: false };
                                                }
                                            """)
                                            
                                            if terms_turnstile.get('found'):
                                                await add_log(f"🛡️ Found Turnstile INSIDE Terms dialog at ({int(terms_turnstile['x'])}, {int(terms_turnstile['y'])})", "INFO")
                                                # Click it
                                                await collection_page.mouse.move(terms_turnstile['x'], terms_turnstile['y'], steps=5)
                                                await asyncio.sleep(0.2)
                                                await collection_page.mouse.click(terms_turnstile['x'], terms_turnstile['y'])
                                                await add_log("✅ Clicked embedded Turnstile in Terms dialog", "SUCCESS")
                                                # Wait for it to verify
                                                await asyncio.sleep(3)
                                        except Exception as e:
                                            await add_log(f"⚠️ Embedded Turnstile check failed: {e}", "DEBUG")
                                        
                                        # Now try to click Agree
                                        terms_dismissed = False
                                        
                                        # IMPORTANT: Wait for any Turnstile verification to complete
                                        # The Terms dialog might have an embedded Turnstile that needs to finish
                                        await add_log("⏳ Waiting for Turnstile to complete (if any)...", "DEBUG")
                                        for turnstile_wait in range(10):  # Wait up to 10 seconds
                                            turnstile_status = await collection_page.evaluate("""
                                                () => {
                                                    // Check for Turnstile iframes
                                                    const iframes = document.querySelectorAll('iframe[src*="challenges.cloudflare.com"]');
                                                    for (const iframe of iframes) {
                                                        const rect = iframe.getBoundingClientRect();
                                                        if (rect.width > 50 && rect.height > 50) {
                                                            // Turnstile is still visible/active
                                                            return { active: true };
                                                        }
                                                    }
                                                    
                                                    // Check for cf-turnstile containers that might be loading
                                                    const containers = document.querySelectorAll('[class*="cf-turnstile"]');
                                                    for (const container of containers) {
                                                        const rect = container.getBoundingClientRect();
                                                        if (rect.width > 50 && rect.height > 50) {
                                                            return { active: true };
                                                        }
                                                    }
                                                    
                                                    return { active: false };
                                                }
                                            """)
                                            
                                            if not turnstile_status.get('active'):
                                                await add_log("✅ Turnstile appears complete", "DEBUG")
                                                break
                                            
                                            await asyncio.sleep(1)
                                            if turnstile_wait == 9:
                                                await add_log("⚠️ Turnstile still active after 10s, proceeding anyway", "WARN")
                                        
                                        for attempt in range(5):  # Increased to 5 attempts
                                            if terms_dismissed:
                                                break
                                            
                                            # Check for Turnstile again before each attempt
                                            await handle_turnstile_modal(collection_page, f"terms_attempt_{attempt + 1}")
                                            
                                            await add_log(f"📜 Terms dismissal attempt {attempt + 1}/5...", "DEBUG")
                                            
                                            # First, scroll the dialog content to make sure Agree is visible
                                            try:
                                                await collection_page.evaluate("""
                                                    () => {
                                                        // Find the dialog
                                                        const dialogs = document.querySelectorAll('[role="dialog"]');
                                                        for (const dialog of dialogs) {
                                                            if (dialog.textContent.includes('Terms of Use')) {
                                                                // Focus the dialog
                                                                dialog.focus();
                                                                
                                                                // Find scrollable containers within dialog
                                                                const scrollables = dialog.querySelectorAll('div');
                                                                for (const div of scrollables) {
                                                                    if (div.scrollHeight > div.clientHeight) {
                                                                        // Scroll to bottom where Agree button usually is
                                                                        div.scrollTop = div.scrollHeight;
                                                                    }
                                                                }
                                                                
                                                                // Also focus the Agree button
                                                                const agreeBtn = dialog.querySelector('button');
                                                                if (agreeBtn && agreeBtn.textContent.includes('Agree')) {
                                                                    agreeBtn.focus();
                                                                }
                                                            }
                                                        }
                                                    }
                                                """)
                                                await asyncio.sleep(0.3)
                                            except:
                                                pass
                                            
                                            # CRITICAL: The dialog says "Or hit Enter on your keyboard to agree"
                                            # But first we need to ensure the dialog/button has focus, NOT the textarea!
                                            await add_log("📜 Clicking Agree button to focus it, then pressing Enter...", "DEBUG")
                                            
                                            # First, click on the Agree button to focus the dialog
                                            try:
                                                agree_btn = collection_page.locator('button:has-text("Agree")').first
                                                if await agree_btn.count() > 0:
                                                    # Just click it - this should both focus AND trigger the action
                                                    await agree_btn.click(timeout=3000)
                                                    await add_log("📜 Clicked Agree button!", "SUCCESS")
                                                    await asyncio.sleep(1)
                                                    
                                                    # Check if it worked
                                                    quick_check = await collection_page.evaluate("""
                                                        () => {
                                                            const buttons = document.querySelectorAll('button');
                                                            for (const btn of buttons) {
                                                                if (btn.textContent.trim() === 'Agree') return false;
                                                            }
                                                            return true;
                                                        }
                                                    """)
                                                    if quick_check:
                                                        await add_log("✅ Terms dialog dismissed!", "SUCCESS")
                                                        terms_dismissed = True
                                                        break
                                            except Exception as e:
                                                await add_log(f"⚠️ Playwright Agree click failed: {e}", "DEBUG")
                                            
                                            # FORCE JS CLICK (New Strategy)
                                            try:
                                                await add_log("📜 Attempting JS Force Click on Agree button...", "DEBUG")
                                                js_click_success = await collection_page.evaluate("""
                                                    () => {
                                                        const buttons = document.querySelectorAll('button');
                                                        for (const btn of buttons) {
                                                            if (btn.textContent.trim() === 'Agree' || btn.textContent.includes('Agree')) {
                                                                btn.click(); // Native DOM click
                                                                return true;
                                                            }
                                                        }
                                                        return false;
                                                    }
                                                """)
                                                if js_click_success:
                                                    await add_log("✅ JS Force Click executed", "SUCCESS")
                                                    await asyncio.sleep(1)
                                            except Exception as e:
                                                await add_log(f"⚠️ JS Force Click failed: {e}", "DEBUG")

                                            # If click didn't work, try clicking the dialog body first, then Enter
                                            try:
                                                # Click somewhere in the dialog to move focus away from textarea
                                                dialog_click = await collection_page.evaluate("""
                                                    () => {
                                                        const dialogs = document.querySelectorAll('[role="dialog"]');
                                                        for (const dialog of dialogs) {
                                                            if (dialog.textContent.includes('Terms of Use')) {
                                                                const rect = dialog.getBoundingClientRect();
                                                                // Find and focus the Agree button
                                                                const agreeBtn = dialog.querySelector('button');
                                                                if (agreeBtn && agreeBtn.textContent.includes('Agree')) {
                                                                    agreeBtn.focus();
                                                                    const btnRect = agreeBtn.getBoundingClientRect();
                                                                    return { x: btnRect.x + btnRect.width / 2, y: btnRect.y + btnRect.height / 2 };
                                                                }
                                                                return { x: rect.x + rect.width / 2, y: rect.y + 50 };
                                                            }
                                                        }
                                                        return null;
                                                    }
                                                """)
                                                if dialog_click:
                                                    # Click to move focus to dialog
                                                    await collection_page.mouse.click(dialog_click['x'], dialog_click['y'])
                                                    await asyncio.sleep(0.3)
                                                    # Now press Enter
                                                    await collection_page.keyboard.press("Enter")
                                                    await add_log("📜 Clicked dialog and pressed Enter", "DEBUG")
                                                    await asyncio.sleep(1)
                                            except Exception as e:
                                                await add_log(f"⚠️ Dialog focus + Enter failed: {e}", "DEBUG")
                                            
                                            # Try Escape key as last resort for this attempt
                                            await collection_page.keyboard.press("Escape")
                                            await asyncio.sleep(0.5)

                                            # Check if it worked
                                            quick_check = await collection_page.evaluate("""
                                                () => {
                                                    const buttons = document.querySelectorAll('button');
                                                    for (const btn of buttons) {
                                                        if (btn.textContent.trim() === 'Agree') return false;
                                                    }
                                                    return true;
                                                }
                                            """)
                                            if quick_check:
                                                await add_log("✅ Terms dialog dismissed via Enter/Escape/JS!", "SUCCESS")
                                                terms_dismissed = True
                                                break
                                            
                                            # Debug: Check button state
                                            try:
                                                btn_debug = await collection_page.evaluate("""
                                                    () => {
                                                        const buttons = document.querySelectorAll('button');
                                                        for (const btn of buttons) {
                                                            if (btn.textContent.trim() === 'Agree' || btn.textContent.includes('Agree')) {
                                                                const rect = btn.getBoundingClientRect();
                                                                const style = window.getComputedStyle(btn);
                                                                
                                                                // Check what element is at the button's center
                                                                const centerX = rect.x + rect.width / 2;
                                                                const centerY = rect.y + rect.height / 2;
                                                                const elemAtPoint = document.elementFromPoint(centerX, centerY);
                                                                
                                                                return {
                                                                    text: btn.textContent.trim(),
                                                                    rect: { x: rect.x, y: rect.y, w: rect.width, h: rect.height },
                                                                    visible: style.visibility,
                                                                    display: style.display,
                                                                    opacity: style.opacity,
                                                                    disabled: btn.disabled,
                                                                    pointer: style.pointerEvents,
                                                                    elemAtPoint: elemAtPoint ? elemAtPoint.tagName + '.' + elemAtPoint.className.substring(0, 30) : 'none',
                                                                    isButtonAtPoint: elemAtPoint === btn || btn.contains(elemAtPoint)
                                                                };
                                                            }
                                                        }
                                                        return null;
                                                    }
                                                """)
                                                if btn_debug:
                                                    await add_log(f"📜 Agree button state: pos=({int(btn_debug['rect']['x'])},{int(btn_debug['rect']['y'])}) size={int(btn_debug['rect']['w'])}x{int(btn_debug['rect']['h'])} disabled={btn_debug['disabled']} pointer={btn_debug['pointer']} elemAtPoint={btn_debug['elemAtPoint']} isButtonAtPoint={btn_debug['isButtonAtPoint']}", "DEBUG")
                                            except Exception as e:
                                                await add_log(f"⚠️ Button debug failed: {e}", "DEBUG")
                                            
                                            # Method 1: Try coordinate-based mouse click (backup)
                                            try:
                                                agree_info = await collection_page.evaluate("""
                                                    () => {
                                                        const buttons = document.querySelectorAll('button');
                                                        for (const btn of buttons) {
                                                            if (btn.textContent.trim() === 'Agree' || btn.textContent.includes('Agree')) {
                                                                // Scroll button into view first
                                                                btn.scrollIntoView({ behavior: 'instant', block: 'center' });
                                                                const rect = btn.getBoundingClientRect();
                                                                return {
                                                                    found: true,
                                                                    x: rect.x + rect.width / 2,
                                                                    y: rect.y + rect.height / 2,
                                                                    width: rect.width,
                                                                    height: rect.height
                                                                };
                                                            }
                                                        }
                                                        return { found: false };
                                                    }
                                                """)
                                                if agree_info.get('found'):
                                                    await add_log(f"📜 Mouse clicking 'Agree' at ({int(agree_info['x'])}, {int(agree_info['y'])})", "DEBUG")
                                                    await collection_page.mouse.move(agree_info['x'], agree_info['y'], steps=10)
                                                    await asyncio.sleep(0.3)
                                                    await collection_page.mouse.click(agree_info['x'], agree_info['y'])
                                                    await asyncio.sleep(0.5)
                                                    
                                                    # Check if it worked
                                                    dialog_gone = await collection_page.evaluate("""
                                                        () => {
                                                            const buttons = document.querySelectorAll('button');
                                                            for (const btn of buttons) {
                                                                if (btn.textContent.trim() === 'Agree') return false;
                                                            }
                                                            return true;
                                                        }
                                                    """)
                                                    if dialog_gone:
                                                        await add_log("✅ Terms dialog dismissed via mouse click!", "SUCCESS")
                                                        terms_dismissed = True
                                                        break
                                            except Exception as e:
                                                await add_log(f"⚠️ Mouse click failed: {e}", "DEBUG")
                                            
                                            # Method 2: JavaScript click with all event types
                                            try:
                                                js_result = await collection_page.evaluate("""
                                                    () => {
                                                        const buttons = document.querySelectorAll('button');
                                                        for (const btn of buttons) {
                                                            if (btn.textContent.trim() === 'Agree' || btn.textContent.includes('Agree')) {
                                                                btn.scrollIntoView({ behavior: 'instant', block: 'center' });
                                                                btn.focus();
                                                                btn.click();
                                                                
                                                                const rect = btn.getBoundingClientRect();
                                                                const centerX = rect.x + rect.width / 2;
                                                                const centerY = rect.y + rect.height / 2;
                                                                
                                                                ['mousedown', 'mouseup', 'click'].forEach(eventType => {
                                                                    btn.dispatchEvent(new MouseEvent(eventType, {
                                                                        bubbles: true,
                                                                        cancelable: true,
                                                                        view: window,
                                                                        clientX: centerX,
                                                                        clientY: centerY
                                                                    }));
                                                                });
                                                                
                                                                ['pointerdown', 'pointerup'].forEach(eventType => {
                                                                    btn.dispatchEvent(new PointerEvent(eventType, {
                                                                        bubbles: true,
                                                                        cancelable: true,
                                                                        view: window,
                                                                        clientX: centerX,
                                                                        clientY: centerY
                                                                    }));
                                                                });
                                                                
                                                                return { clicked: true };
                                                            }
                                                        }
                                                        return { clicked: false };
                                                    }
                                                """)
                                                if js_result.get('clicked'):
                                                    await asyncio.sleep(0.5)
                                                    # Check immediately
                                                    dialog_gone = await collection_page.evaluate("""
                                                        () => {
                                                            const buttons = document.querySelectorAll('button');
                                                            for (const btn of buttons) {
                                                                if (btn.textContent.trim() === 'Agree') return false;
                                                            }
                                                            return true;
                                                        }
                                                    """)
                                                    if dialog_gone:
                                                        await add_log("✅ Terms dialog dismissed via JS!", "SUCCESS")
                                                        terms_dismissed = True
                                                        break
                                            except Exception as e:
                                                await add_log(f"⚠️ JS click failed: {e}", "DEBUG")
                                            
                                            # Method 3: Press Space key (button might be focused from JS)
                                            await collection_page.keyboard.press("Space")
                                            await asyncio.sleep(0.5)
                                            
                                            # Check if Terms dialog was dismissed
                                            dialog_gone = await collection_page.evaluate("""
                                                () => {
                                                    const dialogs = document.querySelectorAll('[role="dialog"]');
                                                    for (const dialog of dialogs) {
                                                        const text = dialog.textContent || '';
                                                        if (text.includes('Terms of Use')) {
                                                            return false;
                                                        }
                                                    }
                                                    const buttons = document.querySelectorAll('button');
                                                    for (const btn of buttons) {
                                                        if (btn.textContent.trim() === 'Agree') {
                                                            return false;
                                                        }
                                                    }
                                                    return true;
                                                }
                                            """)
                                            if dialog_gone:
                                                await add_log("✅ Terms dialog dismissed!", "SUCCESS")
                                                terms_dismissed = True
                                                break
                                            
                                            await asyncio.sleep(0.5)
                                        
                                        if terms_dismissed:
                                            # Terms dismissed, but check for any new Turnstile that might appear
                                            await asyncio.sleep(0.5)
                                            await handle_turnstile_modal(collection_page, "post_terms")
                                            continue  # Go back to check for more dialogs
                                        else:
                                            await add_log("⚠️ Could not dismiss Terms dialog after 5 attempts", "WARN")
                                            await add_log("🔄 Trying page reload with localStorage set...", "INFO")
                                            
                                            # NUCLEAR OPTION: Reload the page after setting localStorage
                                            # The Terms should not appear on reload since we set the flags
                                            try:
                                                # Make sure localStorage is set before reload
                                                await collection_page.evaluate("""
                                                    () => {
                                                        // Set every possible key
                                                        const keys = [
                                                            'terms_accepted', 'termsAccepted', 'tos_accepted', 
                                                            'tosAccepted', 'lmarena_terms', 'arena_terms',
                                                            'hasAcceptedTerms', 'terms-of-use-accepted',
                                                            'privacy_accepted', 'user_terms_accepted'
                                                        ];
                                                        keys.forEach(k => {
                                                            localStorage.setItem(k, 'true');
                                                            localStorage.setItem(k, '1');
                                                            localStorage.setItem(k, JSON.stringify(true));
                                                            localStorage.setItem(k, Date.now().toString());
                                                        });
                                                        
                                                        // Also set a timestamp-based key (some apps use this)
                                                        localStorage.setItem('terms_accepted_at', Date.now().toString());
                                                        localStorage.setItem('tos_version', '1.0');
                                                    }
                                                """)
                                                
                                                # Reload the page
                                                await collection_page.reload(wait_until="domcontentloaded", timeout=30000)
                                                await asyncio.sleep(2)
                                                
                                                # Check if Terms dialog is gone now
                                                terms_after_reload = await collection_page.evaluate("""
                                                    () => {
                                                        const dialogs = document.querySelectorAll('[role="dialog"]');
                                                        for (const dialog of dialogs) {
                                                            if (dialog.textContent && dialog.textContent.includes('Terms of Use')) {
                                                                return true;
                                                            }
                                                        }
                                                        return false;
                                                    }
                                                """)
                                                
                                                if not terms_after_reload:
                                                    await add_log("✅ Page reloaded, Terms dialog gone!", "SUCCESS")
                                                    terms_dismissed = True
                                                    continue  # Continue with dialog loop
                                                else:
                                                    await add_log("⚠️ Terms dialog still present after reload", "WARN")
                                            except Exception as e:
                                                await add_log(f"⚠️ Reload approach failed: {e}", "WARN")
                                            
                                            # Take a screenshot for debugging
                                            try:
                                                debug_screenshot = await collection_page.screenshot()
                                                import base64
                                                b64_debug = base64.b64encode(debug_screenshot).decode()
                                                await add_log(f"📸 Debug screenshot (terms): data:image/png;base64,{b64_debug[:100]}...", "DEBUG")
                                            except:
                                                pass
                                            break
                                    
                                    # No dialogs found, we're done
                                    any_dialog = await collection_page.evaluate("""
                                        () => {
                                            const dialogs = document.querySelectorAll('[role="dialog"]');
                                            for (const dialog of dialogs) {
                                                const rect = dialog.getBoundingClientRect();
                                                if (rect.width > 0 && rect.height > 0) {
                                                    return true;
                                                }
                                            }
                                            return false;
                                        }
                                    """)
                                    
                                    if not any_dialog:
                                        await add_log("✅ All dialogs handled!", "SUCCESS")
                                        break
                                    else:
                                        await add_log("⚠️ Unknown dialog still present, pressing Escape...", "DEBUG")
                                        await collection_page.keyboard.press("Escape")
                                        await asyncio.sleep(0.5)
                                
                                # CRITICAL: After handling dialogs, re-send the message!
                                # CHECK: Skip re-sending if auth token already found
                                if found_auth_token["value"]:
                                    await add_log("⚡ Auth token already found, skipping re-send!", "SUCCESS")
                                else:
                                    await add_log("🔄 Re-sending message after dialogs...", "DEBUG")
                                    try:
                                        # Final check for any blocking dialogs
                                        any_dialog = await collection_page.evaluate("""
                                            () => {
                                                const dialogs = document.querySelectorAll('[role="dialog"]');
                                                for (const dialog of dialogs) {
                                                    const rect = dialog.getBoundingClientRect();
                                                    if (rect.width > 0 && rect.height > 0) {
                                                        return true;
                                                    }
                                                }
                                                return false;
                                            }
                                        """)
                                        if any_dialog:
                                            await add_log("⚠️ Dialog still blocking, pressing Escape...", "DEBUG")
                                            await collection_page.keyboard.press("Escape")
                                            await asyncio.sleep(0.5)
                                        
                                        # Re-focus the textarea
                                        textarea = await collection_page.wait_for_selector(
                                            'textarea[placeholder*="Ask anything"], textarea[placeholder*="Message"], textarea',
                                            timeout=5000
                                        )
                                        if textarea:
                                            await textarea.click(timeout=2000)
                                            await asyncio.sleep(0.3)
                                            
                                            # Check if textarea has content, if not re-type
                                            textarea_value = await textarea.input_value()
                                            if not textarea_value or not textarea_value.strip():
                                                await add_log("📝 Textarea empty, re-typing message...", "DEBUG")
                                                await textarea.type("Hello!", delay=50)
                                                await asyncio.sleep(0.3)
                                            
                                            # Send the message
                                            # Try clicking the send button explicitly first
                                            send_clicked = False
                                            try:
                                                send_btn = await collection_page.wait_for_selector(
                                                    'button[aria-label="Send"], button[data-testid="send-button"], button:has-text("Send")',
                                                    timeout=2000
                                                )
                                                if send_btn:
                                                    await send_btn.click()
                                                    send_clicked = True
                                                    await add_log("✅ Clicked Send button!", "SUCCESS")
                                            except:
                                                pass
                                            
                                            if not send_clicked:
                                                await collection_page.keyboard.press("Enter")
                                                await add_log("✅ Pressed Enter to send!", "SUCCESS")
                                            
                                            # Check for any NEW dialogs that might appear after sending
                                            await asyncio.sleep(2)
                                            await handle_turnstile_modal(collection_page, "post_send")
                                    except Exception as e:
                                        await add_log(f"⚠️ Re-send failed: {e}", "DEBUG")
                                
                                # Brief wait for auth token trigger
                                await asyncio.sleep(2)
                                
                                # Check localStorage and sessionStorage for auth token
                                try:
                                    storage_check = await collection_page.evaluate("""
                                        () => {
                                            const result = {
                                                localStorage: {},
                                                sessionStorage: {},
                                                cookies: document.cookie
                                            };
                                            
                                            // Check localStorage
                                            for (let i = 0; i < localStorage.length; i++) {
                                                const key = localStorage.key(i);
                                                if (key.includes('auth') || key.includes('token') || key.includes('arena') || key.includes('user')) {
                                                    result.localStorage[key] = localStorage.getItem(key).substring(0, 200);
                                                }
                                            }
                                            
                                            // Check sessionStorage
                                            for (let i = 0; i < sessionStorage.length; i++) {
                                                const key = sessionStorage.key(i);
                                                if (key.includes('auth') || key.includes('token') || key.includes('arena') || key.includes('user')) {
                                                    result.sessionStorage[key] = sessionStorage.getItem(key).substring(0, 200);
                                                }
                                            }
                                            
                                            return result;
                                        }
                                    """)
                                    if storage_check['localStorage']:
                                        await add_log(f"📦 localStorage: {storage_check['localStorage']}", "DEBUG")
                                    if storage_check['sessionStorage']:
                                        await add_log(f"📦 sessionStorage: {storage_check['sessionStorage']}", "DEBUG")
                                    if 'arena-auth' in storage_check['cookies']:
                                        await add_log(f"🍪 Found auth in cookies via JS!", "SUCCESS")
                                        
                                    # Force check cookies via Playwright
                                    cookies = await collection_context.cookies()
                                    for cookie in cookies:
                                        if cookie['name'] == 'arena-auth-prod-v1':
                                            found_auth_token["value"] = cookie['value']
                                            await add_log(f"🎯 AUTH TOKEN FOUND in context cookies!", "SUCCESS")
                                            
                                except Exception as e:
                                    await add_log(f"⚠️ Storage check error: {e}", "DEBUG")
                                
                                textarea_found = True
                                break
                        except Exception as e:
                            await add_log(f"⚠️ Failed to interact with {selector}: {e}", "DEBUG")
                            continue
                    
                    if not textarea_found:
                        await add_log(f"⚠️ No chat input found, trying generic interaction", "DEBUG")
                        # Fallback: Click on page body and scroll
                        await collection_page.click("body", timeout=5000)
                    
                    await asyncio.sleep(0.5)
                    
                    # ============================================================
                    # FALLBACK: If no token found yet, try calling sign-up API directly
                    # The auth token is generated by /nextjs-api/sign-up endpoint
                    # ============================================================
                    if not found_auth_token["value"]:
                        await add_log("🔄 No token yet, trying direct API call to sign-up...", "DEBUG")
                        try:
                            # Call the sign-up API directly using the page context
                            signup_result = await collection_page.evaluate("""
                                async () => {
                                    try {
                                        const response = await fetch('/nextjs-api/sign-up', {
                                            method: 'POST',
                                            headers: {
                                                'Content-Type': 'application/json',
                                            },
                                            credentials: 'include'
                                        });
                                        return { status: response.status, ok: response.ok };
                                    } catch (e) {
                                        return { error: e.message };
                                    }
                                }
                            """)
                            await add_log(f"📡 Sign-up API result: {signup_result}", "DEBUG")
                            
                            # Check cookies again after API call
                            await asyncio.sleep(1)
                            cookies = await collection_context.cookies()
                            for cookie in cookies:
                                if cookie['name'] == 'arena-auth-prod-v1':
                                    found_auth_token["value"] = cookie['value']
                                    await add_log(f"🎯 AUTH TOKEN FOUND after direct API call!", "SUCCESS")
                                    break
                        except Exception as api_err:
                            await add_log(f"⚠️ Direct API call failed: {api_err}", "DEBUG")
                    
                except Exception as click_err:
                    await add_log(f"⚠️ Interaction: {click_err}", "DEBUG")
                
                # Brief wait then check for token
                await asyncio.sleep(1)
                
                # Poll for the auth cookie (shorter wait since network response is usually faster)
                auth_cookie = None
                max_wait = 20  # Increased wait time since auth might take longer
                poll_interval = 0.5
                elapsed = 0
                
                while elapsed < max_wait:
                    # First check if we found the token via network response
                    if found_auth_token["value"]:
                        await add_log(f"🎯 Using token found from network response!", "SUCCESS")
                        token_value = found_auth_token["value"]
                        
                        # Add to collected tokens list
                        if token_value not in existing_tokens and token_value not in collected_tokens:
                            collected_tokens.append(token_value)
                            existing_tokens.add(token_value)
                            token_collection_status["collected"] += 1
                            
                            # Save to config
                            config = get_config()
                            current_tokens = config.get("auth_tokens", [])
                            current_tokens.append(token_value)
                            config["auth_tokens"] = current_tokens
                            save_config(config)
                            
                            await add_log(f"✅ Token {i + 1}/{count} collected from network!", "SUCCESS")
                            
                            # Immediately clear cookies and reload for next collection
                            if i < count - 1:  # Not the last iteration
                                await add_log(f"🔄 Clearing cookies and reloading for next token...", "DEBUG")
                                try:
                                    await collection_context.clear_cookies()
                                    await asyncio.sleep(0.5)
                                    await collection_page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=60000)
                                    await add_log(f"✅ Page reloaded, ready for next collection", "DEBUG")
                                except Exception as reload_err:
                                    await add_log(f"⚠️ Reload error: {reload_err}", "WARN")
                        else:
                            await add_log(f"⚠️ Token already exists, skipping", "WARN")
                        
                        found_auth_token["value"] = None  # Reset for next collection
                        break
                    
                    cookies = await collection_context.cookies()
                    auth_cookie = next(
                        (c for c in cookies if c['name'] == 'arena-auth-prod-v1'), 
                        None
                    )
                    
                    if auth_cookie:
                        break
                    
                    await asyncio.sleep(poll_interval)
                    elapsed += poll_interval
                    
                    # Log progress every few seconds
                    if elapsed % 5 == 0:
                        await add_log(f"⏳ Still waiting for token... ({int(elapsed)}s)", "DEBUG")
                
                if auth_cookie:
                    token_value = auth_cookie['value']
                    
                    # Check for duplicates
                    if token_value not in existing_tokens and token_value not in [t for t in collected_tokens]:
                        collected_tokens.append(token_value)
                        existing_tokens.add(token_value)
                        token_collection_status["collected"] = len(collected_tokens)
                        await add_log(f"✅ Token {len(collected_tokens)}/{count} collected: {token_value[:30]}...", "SUCCESS")
                        
                        # Add to config immediately
                        config = get_config()
                        current_tokens = config.get("auth_tokens", [])
                        if token_value not in current_tokens:
                            current_tokens.append(token_value)
                            config["auth_tokens"] = current_tokens
                            save_config(config)
                            await add_log("💾 Token saved to config", "INFO")
                        
                        # Immediately clear cookies and reload for next collection
                        if i < count - 1:  # Not the last iteration
                            await add_log(f"🔄 Clearing cookies for next token...", "DEBUG")
                            try:
                                await collection_context.clear_cookies()
                                await collection_page.goto("https://lmarena.ai/?mode=direct", wait_until="domcontentloaded", timeout=30000)
                            except Exception as reload_err:
                                await add_log(f"⚠️ Reload error: {reload_err}", "WARN")
                    else:
                        await add_log(f"⚠️ Duplicate token found, will retry...", "WARN")
                        i -= 1
                elif token_collection_status["collected"] > i:
                    # Token was already collected via network response, skip this warning
                    pass
                else:
                    await add_log(f"⚠️ No auth cookie found after {max_wait}s on attempt {i + 1}", "WARN")
                    token_collection_status["errors"].append(f"No cookie on attempt {i + 1}")
                    
                    # Take a screenshot for debugging
                    try:
                        await collection_page.screenshot(path=f"debug_failure_{i}.png")
                        await add_log(f"📸 Saved debug screenshot to debug_failure_{i}.png", "INFO")
                    except Exception as e:
                        await add_log(f"⚠️ Failed to take screenshot: {e}", "WARN")
                
                # Delay between collections
                if i < count - 1 and token_collection_status["running"]:
                    token_collection_status["current_status"] = f"Waiting {delay}s before next collection..."
                    await asyncio.sleep(delay)
                    
            except Exception as e:
                error_msg = f"Error on attempt {i + 1}: {str(e)}"
                await add_log(f"❌ {error_msg}", "ERROR")
                token_collection_status["errors"].append(error_msg)
                await asyncio.sleep(2)  # Brief pause before retry
                continue
        
        # Save collected tokens to config
        if collected_tokens:
            config = get_config()
            existing = config.get("auth_tokens", [])
            for token in collected_tokens:
                if token not in existing:
                    existing.append(token)
            config["auth_tokens"] = existing
            save_config(config)
            await add_log(f"💾 Saved {len(collected_tokens)} new tokens to config", "SUCCESS")
        
        token_collection_status["current_status"] = f"✅ Complete! Collected {len(collected_tokens)} tokens"
        await add_log(f"🎉 Collection complete! {len(collected_tokens)} new tokens collected.", "SUCCESS")
            
    except Exception as e:
        token_collection_status["current_status"] = f"❌ Error: {str(e)}"
        await add_log(f"❌ Collection error: {str(e)}", "ERROR")
    finally:
        # Clean up the collection context (NOT the global browser!)
        token_collection_status["running"] = False
        try:
            if collection_page:
                await collection_page.close()
            if collection_context:
                await collection_context.close()
            await add_log("🧹 Collection context closed (Global browser kept alive)", "DEBUG")
        except Exception as e:
            await add_log(f"⚠️ Error closing collection context: {e}", "WARN")
    
    return collected_tokens

@app.post("/v1/chat/completions")
async def api_chat_completions(request: Request, api_key: dict = Depends(rate_limit_api_key)):
    global active_generations
    
    # Block requests during token collection to avoid race conditions
    if token_collection_status["running"]:
        raise HTTPException(
            status_code=503,
            detail="Service temporarily unavailable: Token collection in progress. Please retry in a few seconds.",
            headers={"Retry-After": "10"}
        )
    
    active_generations += 1
    should_decrement = True
    try:
        # Generate fresh reCAPTCHA token for this request
        debug_print("🔄 Generating fresh reCAPTCHA token for this request...")
        await refresh_recaptcha_token()

        # Load config to ensure we have the latest token and it's available for later use
        config = get_config()

        debug_print("\n" + "="*80)
        debug_print("🔵 NEW API REQUEST RECEIVED")
        debug_print("="*80)
        await add_log("🔵 New API request received", "INFO")
        
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
        
        # --- GENERATION PARAMETERS ---
        # Use config defaults, but allow frontend to override
        config = get_config()
        default_temp = config.get("default_temperature", 0.7)
        default_top_p = config.get("default_top_p", 1.0)
        default_max_tokens = config.get("default_max_tokens", 64000)
        
        # Frontend (SillyTavern, etc.) can override these by sending them in the request
        temperature = body.get("temperature") if body.get("temperature") is not None else default_temp
        top_p = body.get("top_p") if body.get("top_p") is not None else default_top_p
        max_tokens = body.get("max_tokens") if body.get("max_tokens") is not None else default_max_tokens
        
        # Build generation_params dict (will be added to payload later)
        generation_params = {
            "temperature": temperature,
            "top_p": top_p,
            "max_new_tokens": max_tokens
        }
        debug_print(f"⚙️ Generation params: {generation_params}")
        
        debug_print(f"🌊 Stream mode: {stream}")
        debug_print(f"🤖 Requested model: {model_public_name}")
        debug_print(f"💬 Number of messages: {len(messages)}")
        await add_log(f"🤖 Model: {model_public_name} | Stream: {stream} | Messages: {len(messages)}", "INFO")
        
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
        import time
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
                "parameters": generation_params,  # <-- KEY FIX: Add generation parameters from working script
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
                    impersonate_target = "firefox133"
                    debug_print(f"🎭 Impersonating: {impersonate_target}")
                    
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
                            else:
                                # Add a smaller delay for subsequent chunks to avoid bursting
                                chunk_delay = random.uniform(0.2, 0.8)
                                debug_print(f"⏳ Chunk delay: {chunk_delay:.2f}s")
                                await asyncio.sleep(chunk_delay)
                        
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
                                async with AsyncSession(impersonate=impersonate_target) as client:
                                    # Note: curl_cffi stream API is slightly different
                                    response = await client.post(url, json=payload, headers=chunk_headers, timeout=120, stream=True)
                                    
                                    if response.status_code == 403:
                                        debug_print(f"❌ 403 Forbidden. Response: {await response.atext()}")
                                        # Try to print headers to see what we sent
                                        debug_print(f"   Sent Headers: {chunk_headers.keys()}")
                                        debug_print(f"   Sent Cookie: {chunk_headers.get('Cookie')[:50]}...")
                                    
                                    # HANDLE 429 (Rate Limit), 401 (Unauthorized), and 403 (Forbidden)
                                    if response.status_code in [429, 401, 403, 400]:
                                        error_type = "Rate Limit" if response.status_code == 429 else "Auth/Bad Request Error"
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
                                        
                                        # Count tokens for streaming response
                                        global total_tokens_generated
                                        try:
                                            enc = tiktoken.get_encoding("cl100k_base")
                                            stream_tokens = len(enc.encode(current_response_text))
                                            total_tokens_generated += stream_tokens
                                            debug_print(f"✅ Stream complete | Tokens: {stream_tokens}")
                                        except Exception:
                                            total_tokens_generated += len(current_response_text) // 4
                                            debug_print(f"✅ Stream complete | Tokens: ~{len(current_response_text) // 4}")
                                                
                                        yield "data: [DONE]\n\n"
                                        debug_print(f"✅ Stream completed")
                                    
                                    # Success - break retry loop
                                    break
                            
                            except ImpersonateError as e:
                                print(f"⚠️ Impersonation error: {e}. Falling back to chrome120.")
                                impersonate_target = "chrome120"
                                continue # Retry immediately with new target

                            except (HTTPError, Timeout, RequestsError, ConnectionError) as e:
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
            impersonate_target = "firefox133"
            
            # Compatibility Check
            try:
                async with AsyncSession(impersonate=impersonate_target) as check_client:
                    await check_client.head("https://www.google.com", timeout=2)
            except (ImpersonateError, Exception):
                debug_print(f"⚠️ {impersonate_target} not supported/failed. Falling back to chrome120.")
                impersonate_target = "chrome120"

            debug_print(f"🎭 Impersonating (Non-Stream): {impersonate_target}")

            async with AsyncSession(impersonate=impersonate_target) as client:
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
                        else:
                            # Add a smaller delay for subsequent chunks to avoid bursting
                            chunk_delay = random.uniform(0.2, 0.8)
                            debug_print(f"⏳ Chunk delay: {chunk_delay:.2f}s")
                            await asyncio.sleep(chunk_delay)

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
                            if response.status_code in [429, 401, 403, 400]:
                                error_type = "Rate Limit" if response.status_code == 429 else "Auth/Bad Request Error"
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

                            # Count tokens using tiktoken (approximate with cl100k_base)
                            global total_tokens_generated
                            try:
                                enc = tiktoken.get_encoding("cl100k_base")
                                prompt_tokens = len(enc.encode(prompt))
                                completion_tokens = len(enc.encode(current_response_text))
                                total_tokens_generated += completion_tokens
                                debug_print(f"✅ Response complete | Prompt: {prompt_tokens} | Completion: {completion_tokens}")
                            except Exception:
                                # Fallback to character-based estimation
                                prompt_tokens = len(prompt) // 4
                                completion_tokens = len(current_response_text) // 4
                                total_tokens_generated += completion_tokens
                                debug_print(f"✅ Response complete | Prompt: ~{prompt_tokens} | Completion: ~{completion_tokens}")

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
                                    "prompt_tokens": prompt_tokens,
                                    "completion_tokens": completion_tokens,
                                    "total_tokens": prompt_tokens + completion_tokens
                                }
                            }
                            
                            debug_print(f"\n✅ REQUEST COMPLETED SUCCESSFULLY")
                            debug_print("="*80 + "\n")
                            
                            return final_response
                        
                        except (HTTPError, Timeout, RequestsError, ConnectionError) as e:
                            print(f"❌ Request error (curl_cffi): {str(e)}")
                            
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

                            # If we run out of retries
                            return {
                                "error": {
                                    "message": f"Upstream error: {str(e)}",
                                    "type": "upstream_error",
                                    "code": 502
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
