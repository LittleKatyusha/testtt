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
from fastapi.middleware.cors import CORSMiddleware
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
CHUNK_ROTATION_LIMIT = 5 

# Set to True to reuse the same LMArena session ID for the same API Key + Model.
# This mimics "Direct Chat" behavior and can help bypass "New Session" rate limits (422/429).
STICKY_SESSIONS = True

# FAKE HISTORY MODE (Recommended!)
# When True: All chunks are bundled into a SINGLE request as fake chat history.
#   - Chunk 1 becomes a "user" message in history with a fake "assistant" acknowledgment
#   - Chunk 2 becomes another "user" message in history with a fake "assistant" acknowledgment  
#   - Only the LAST chunk is sent as the actual new message
#   - This avoids multiple API calls and rate limits entirely!
# When False: Uses the old sequential chunk sending (triggers rate limits on large prompts)
FAKE_HISTORY_MODE = True
# ============================================================

async def refresh_recaptcha_token():
    """Safer reCAPTCHA refresher:
    - If the current page contains Cloudflare Turnstile, do NOT attempt to inject grecaptcha.
      Instead return None (Turnstile is handled separately and we rely on cookies/__cf_bm).
    - If grecaptcha is actually present on the page, attempt a short, guarded execute and cache result.
    """
    global global_page, cached_recaptcha_token, cached_recaptcha_timestamp

    # Use the same TTL logic if we already have a genuine cached token
    current_time = time.time()
    try:
        ttl = RECAPTCHA_TOKEN_CACHE_TTL
    except Exception:
        ttl = 100
    if cached_recaptcha_token and (current_time - cached_recaptcha_timestamp) < ttl:
        age = int(current_time - cached_recaptcha_timestamp)
        print(f"✅ Using cached reCAPTCHA token (age: {age}s / {ttl}s TTL)")
        return cached_recaptcha_token

    page = global_page
    if not page:
        print("❌ No active page found for reCAPTCHA generation")
        return None

    # Quick checks in page to decide which challenge is present
    try:
        # 1) If Turnstile iframe present -> DO NOT attempt grecaptcha injection
        has_turnstile = await page.evaluate("""
            () => !!Array.from(document.querySelectorAll('iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"]')).find(i => {
                const r = i.getBoundingClientRect(); return r.width > 20 && r.height > 20;
            })
        """)
        if has_turnstile:
            print("ℹ️ Cloudflare Turnstile detected on page — skipping grecaptcha extraction.")
            # Ensure cookies (cf_clearance / __cf_bm) are captured by saving page context cookies
            try:
                cookies = await page.context.cookies()
                if cookies:
                    config = get_config()
                    cookie_parts = [f"{c['name']}={c['value']}" for c in cookies]
                    config['cookie_string'] = '; '.join(cookie_parts)
                    # update cf_clearance if present
                    cf = next((c['value'] for c in cookies if c.get('name')=='cf_clearance'), '')
                    if cf:
                        config['cf_clearance'] = cf
                    ua = await page.evaluate("navigator.userAgent")
                    config['user_agent'] = ua
                    save_config(config)
                    print(f"✅ Saved cookies after Turnstile (cookies: {len(cookies)})")
            except Exception as e:
                print(f"⚠️ Failed saving cookies after Turnstile: {e}")
            # Turnstile flow does not return a grecaptcha token
            return None

        # 2) If grecaptcha is defined, attempt a short execute
        is_grecaptcha = await page.evaluate("typeof grecaptcha !== 'undefined' || typeof window.grecaptcha !== 'undefined'")
        if not is_grecaptcha:
            # Don't try to inject a grecaptcha library anymore — it's fragile and likely incorrect here.
            print("⚠️ grecaptcha not found on page. Skipping injection (Turnstile likely used).")
            return None

        print("✅ grecaptcha detected — attempting to locate site key and execute (short timeout).")

        # Try to find site key in page (script/render or inline)
        content = await page.content()
        site_key = None

        import re as _re
        mm = _re.search(r'grecaptcha\.execute\(["\']([^"\']+)["\']', content)
        if not mm:
            mm = _re.search(r'sitekey["\']?\s*[:=]\s*["\']([^"\']+)["\']', content)
        if not mm:
            # Fallback: Check for data-sitekey attribute in HTML tags
            mm = _re.search(r'data-sitekey=["\']([^"\']+)["\']', content)
        
        if mm:
            site_key = mm.group(1)
            print(f"✅ Found reCAPTCHA site key via regex: {site_key}")

        if not site_key:
            # try to detect from script tags with render=
            script_src = await page.evaluate('''() => {
                const s = Array.from(document.querySelectorAll('script[src*="recaptcha"]')).map(x=>x.src);
                return s.find(u => u && u.includes('render='));
            }''')
            if script_src:
                try:
                    import urllib.parse as _up
                    parsed = _up.urlparse(script_src)
                    qs = _up.parse_qs(parsed.query)
                    if 'render' in qs:
                        site_key = qs['render'][0]
                        print(f"✅ Found site key from script src: {site_key}")
                except Exception:
                    pass

        if not site_key:
            print("⚠️ Could not find a reCAPTCHA site key — aborting grecaptcha execute.")
            return None

        # Execute grecaptcha with a short guarded promise (will return None on failure)
        try:
            token = await page.evaluate(f"""
                new Promise((resolve) => {{
                    try {{
                        const g = window.grecaptcha || grecaptcha;
                        if (!g) return resolve(null);
                        g.ready(() => {{
                            g.execute('{site_key}', {{action: 'submit'}})
                              .then(t => resolve(t))
                              .catch(_ => resolve(null));
                        }});
                    }} catch (e) {{ resolve(null); }}
                }})
            """, timeout=20000)
        except Exception as e:
            print(f"⚠️ grecaptcha execute failed: {e}")
            token = None

        if token:
            print(f"✅ Generated reCAPTCHA token (trim): {token[:20]}...")
            try:
                config = get_config()
                config['recaptcha_token'] = token
                save_config(config)
            except Exception:
                pass
            cached_recaptcha_token = token
            cached_recaptcha_timestamp = time.time()
            return token
        else:
            print("⚠️ grecaptcha execute returned no token.")
            return None

    except Exception as e:
        print(f"❌ Exception in refresh_recaptcha_token: {e}")
        return None

# --- OPTIMIZATION: Fast JSON Serialization ---
try:
    import orjson
    # orjson returns bytes, so we decode to str for f-string compatibility
    def fast_json_dumps(data):
        return orjson.dumps(data).decode('utf-8')
    print("⚡ Using orjson for high-performance serialization")
except ImportError:
    import json
    def fast_json_dumps(data):
        return json.dumps(data)
    print("⚠️ orjson not found, falling back to standard json (slower)")

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

# Configure CORS to allow requests from web-based frontends like JanitorAI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (janitorai.com, localhost, etc.)
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, OPTIONS, etc.)
    allow_headers=["*"],  # Allows all headers
)

# --- Custom Exceptions ---
class UpstreamRateLimitError(Exception):
    """Raised when upstream provider (Google, OpenAI, etc.) returns a rate limit error in stream"""
    pass

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

# --- Activity Log for Dashboard (per-request tracking) ---
ACTIVITY_LOG_SIZE = 50
activity_log: List[dict] = []  # Stores {timestamp, model, tokens, status}

def add_activity(model: str, tokens: int, status: str = "success"):
    """Add a request activity entry"""
    global activity_log
    activity_log.append({
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "model": model,
        "tokens": tokens,
        "status": status
    })
    if len(activity_log) > ACTIVITY_LOG_SIZE:
        activity_log = activity_log[-ACTIVITY_LOG_SIZE:]

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

_config_cache = None

def get_config(force_reload=False):
    global _config_cache
    if _config_cache is not None and not force_reload:
        return _config_cache

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
    config.setdefault("default_presence_penalty", 0.0)
    config.setdefault("default_frequency_penalty", 0.0)
    
    # Advanced Settings
    config.setdefault("chunk_size", 110000)
    config.setdefault("chunk_rotation_limit", 5)
    
    # Token auto-collection settings
    config.setdefault("token_collect_count", 15)
    config.setdefault("token_collect_delay", 2)  # seconds between collections
    
    _config_cache = config
    return config

def load_usage_stats():
    """Load usage stats from config into memory"""
    global model_usage_stats
    config = get_config(force_reload=True) # Force load on startup
    raw_stats = config.get("usage_stats", {})
    
    # Migration: Convert old int stats to new dict stats
    migrated_stats = defaultdict(lambda: {"count": 0, "tokens": 0, "last_used": 0})
    
    for model, value in raw_stats.items():
        if isinstance(value, int):
            migrated_stats[model] = {"count": value, "tokens": 0, "last_used": 0}
        else:
            migrated_stats[model] = value
            
    model_usage_stats = migrated_stats

def save_config(config):
    global _config_cache
    # Persist in-memory stats to the config dict before saving
    config["usage_stats"] = dict(model_usage_stats)
    
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
    
    # Update the cache with a copy of the saved config
    _config_cache = config.copy()
    debug_print(f"✅ Config saved and cache updated")

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

                # Wait for title change OR cf_clearance cookie
                start_wait = time.time()
                challenge_passed = False
                
                while time.time() - start_wait < 60:
                    # Check title
                    try:
                        title = await page.title()
                        if "Just a moment" not in title:
                            await add_log(f"✅ Title changed to: {title}", "SUCCESS")
                            challenge_passed = True
                            break
                    except:
                        pass
                        
                    # Check cookie
                    try:
                        cookies = await page.context.cookies()
                        if any(c['name'] == 'cf_clearance' for c in cookies):
                            await add_log("✅ Found cf_clearance cookie!", "SUCCESS")
                            challenge_passed = True
                            break
                    except:
                        pass
                        
                    await asyncio.sleep(1)
                
                if not challenge_passed:
                    raise Exception("Timeout waiting for challenge to complete")

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
    global active_generations, token_collection_status
    while True:
        # Skip refresh if token collection is running to avoid interference
        if token_collection_status.get("running", False):
            await asyncio.sleep(30)  # Check again in 30s
            continue
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
    # Load leaderboard cache
    load_leaderboard_cache()
    # Log startup
    await add_log("🚀 LMArena Bridge starting up...", "INFO")
    await add_log(f"📍 Dashboard: http://localhost:{PORT}/dashboard", "INFO")
    await add_log(f"📚 API Base URL: http://localhost:{PORT}/v1", "INFO")
    # Start initial data fetch
    asyncio.create_task(get_initial_data())
    # Update leaderboard in background
    asyncio.create_task(update_leaderboard_on_startup())
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
    
    error_msg = '<div class="error-message"><span class="error-icon">⚠️</span> Invalid password. Please try again.</div>' if error else ''
    
    return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - LMArena Bridge</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
            <style>
                :root {{
                    --primary: #3b82f6;
                    --primary-light: #60a5fa;
                    --primary-dark: #1d4ed8;
                    --secondary: #6366f1;
                    --accent: #0ea5e9;
                    --bg: #020617;
                    --bg-card: #0a1628;
                    --bg-input: #162033;
                    --text: #f1f5f9;
                    --text-muted: #64748b;
                    --text-secondary: #94a3b8;
                    --border: #1e3a5f;
                    --danger: #ef4444;
                    --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                }}
                
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                
                body {{
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: var(--bg);
                    background-image: 
                        radial-gradient(ellipse at 20% 20%, rgba(59, 130, 246, 0.1) 0%, transparent 50%),
                        radial-gradient(ellipse at 80% 80%, rgba(99, 102, 241, 0.08) 0%, transparent 50%),
                        radial-gradient(ellipse at 50% 50%, rgba(14, 165, 233, 0.05) 0%, transparent 70%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    overflow: hidden;
                }}
                
                /* Animated background particles */
                .bg-particles {{
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    pointer-events: none;
                    z-index: 0;
                }}
                
                .particle {{
                    position: absolute;
                    width: 3px;
                    height: 3px;
                    background: var(--primary);
                    border-radius: 50%;
                    opacity: 0;
                    animation: float-particle 12s infinite;
                }}
                
                @keyframes float-particle {{
                    0%, 100% {{ opacity: 0; transform: translateY(100vh) scale(0); }}
                    10% {{ opacity: 0.5; }}
                    90% {{ opacity: 0.5; }}
                    100% {{ opacity: 0; transform: translateY(-100vh) scale(1); }}
                }}
                
                .login-wrapper {{
                    text-align: center;
                    position: relative;
                    z-index: 1;
                    animation: fadeInUp 0.8s ease;
                }}
                
                @keyframes fadeInUp {{
                    from {{
                        opacity: 0;
                        transform: translateY(30px);
                    }}
                    to {{
                        opacity: 1;
                        transform: translateY(0);
                    }}
                }}
                
                .logo {{
                    font-size: 64px;
                    margin-bottom: 20px;
                    filter: drop-shadow(0 0 30px rgba(59, 130, 246, 0.5));
                    animation: pulse-logo 3s ease-in-out infinite;
                }}
                
                @keyframes pulse-logo {{
                    0%, 100% {{ 
                        transform: scale(1); 
                        filter: drop-shadow(0 0 20px rgba(59, 130, 246, 0.4));
                    }}
                    50% {{ 
                        transform: scale(1.05); 
                        filter: drop-shadow(0 0 40px rgba(59, 130, 246, 0.6));
                    }}
                }}
                
                .brand-title {{
                    font-size: 36px;
                    font-weight: 800;
                    background: linear-gradient(135deg, #ffffff 0%, var(--primary-light) 50%, var(--accent) 100%);
                    background-size: 200% 200%;
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    background-clip: text;
                    animation: gradient-shift 5s ease infinite;
                    margin-bottom: 10px;
                    letter-spacing: -1px;
                }}
                
                @keyframes gradient-shift {{
                    0%, 100% {{ background-position: 0% 50%; }}
                    50% {{ background-position: 100% 50%; }}
                }}
                
                .brand-subtitle {{
                    color: var(--text-muted);
                    font-size: 15px;
                    margin-bottom: 40px;
                    font-weight: 400;
                }}
                
                .login-container {{
                    background: linear-gradient(145deg, var(--bg-card) 0%, rgba(15, 29, 50, 0.8) 100%);
                    padding: 44px;
                    border-radius: 24px;
                    border: 1px solid var(--border);
                    width: 100%;
                    max-width: 420px;
                    box-shadow: 
                        0 25px 50px -12px rgba(0, 0, 0, 0.5),
                        0 0 50px rgba(59, 130, 246, 0.1);
                    position: relative;
                    overflow: hidden;
                    backdrop-filter: blur(20px);
                }}
                
                .login-container::before {{
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    height: 1px;
                    background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.5), transparent);
                }}
                
                .login-container::after {{
                    content: '';
                    position: absolute;
                    top: -50%;
                    left: -50%;
                    width: 200%;
                    height: 200%;
                    background: radial-gradient(circle, rgba(59, 130, 246, 0.03) 0%, transparent 60%);
                    pointer-events: none;
                }}
                
                h2 {{
                    color: var(--text);
                    margin-bottom: 8px;
                    font-size: 26px;
                    font-weight: 700;
                    position: relative;
                    z-index: 1;
                }}
                
                .subtitle {{
                    color: var(--text-secondary);
                    margin-bottom: 28px;
                    font-size: 14px;
                    position: relative;
                    z-index: 1;
                }}
                
                .form-group {{
                    margin-bottom: 24px;
                    text-align: left;
                    position: relative;
                    z-index: 1;
                }}
                
                label {{
                    display: block;
                    margin-bottom: 10px;
                    color: var(--text-secondary);
                    font-weight: 600;
                    font-size: 13px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }}
                
                input[type="password"] {{
                    width: 100%;
                    padding: 16px 20px;
                    background: linear-gradient(135deg, var(--bg) 0%, var(--bg-input) 100%);
                    border: 1px solid var(--border);
                    border-radius: 14px;
                    font-size: 15px;
                    color: var(--text);
                    transition: var(--transition);
                    font-family: inherit;
                }}
                
                input[type="password"]::placeholder {{
                    color: var(--text-muted);
                }}
                
                input[type="password"]:focus {{
                    outline: none;
                    border-color: var(--primary);
                    box-shadow: 
                        0 0 0 4px rgba(59, 130, 246, 0.15),
                        0 0 30px rgba(59, 130, 246, 0.1);
                    transform: translateY(-2px);
                }}
                
                button {{
                    width: 100%;
                    padding: 16px;
                    background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
                    color: white;
                    border: none;
                    border-radius: 14px;
                    font-size: 15px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: var(--transition);
                    position: relative;
                    z-index: 1;
                    overflow: hidden;
                    box-shadow: 
                        0 4px 15px rgba(59, 130, 246, 0.3),
                        inset 0 1px 0 rgba(255, 255, 255, 0.1);
                }}
                
                button::before {{
                    content: '';
                    position: absolute;
                    top: 0;
                    left: -100%;
                    width: 100%;
                    height: 100%;
                    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
                    transition: left 0.5s ease;
                }}
                
                button:hover::before {{
                    left: 100%;
                }}
                
                button:hover {{
                    background: linear-gradient(135deg, var(--primary-light) 0%, var(--primary) 100%);
                    transform: translateY(-3px);
                    box-shadow: 
                        0 8px 25px rgba(59, 130, 246, 0.4),
                        0 0 40px rgba(59, 130, 246, 0.2);
                }}
                
                button:active {{
                    transform: translateY(-1px);
                }}
                
                .error-message {{
                    background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(239, 68, 68, 0.1) 100%);
                    color: #fca5a5;
                    padding: 14px 18px;
                    border-radius: 12px;
                    margin-bottom: 24px;
                    border: 1px solid rgba(239, 68, 68, 0.3);
                    font-size: 14px;
                    text-align: left;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    animation: shake 0.5s ease;
                    position: relative;
                    z-index: 1;
                }}
                
                .error-icon {{
                    font-size: 18px;
                }}
                
                @keyframes shake {{
                    0%, 100% {{ transform: translateX(0); }}
                    20%, 60% {{ transform: translateX(-5px); }}
                    40%, 80% {{ transform: translateX(5px); }}
                }}
                
                .credits {{
                    margin-top: 32px;
                    color: var(--text-muted);
                    font-size: 13px;
                }}
                
                .credits a {{
                    color: var(--primary-light);
                    text-decoration: none;
                    transition: var(--transition);
                    font-weight: 500;
                }}
                
                .credits a:hover {{
                    color: var(--accent);
                    text-shadow: 0 0 10px rgba(14, 165, 233, 0.5);
                }}
                
                /* Mobile responsive */
                @media (max-width: 480px) {{
                    .login-container {{
                        padding: 32px 24px;
                    }}
                    
                    .brand-title {{
                        font-size: 28px;
                    }}
                    
                    .logo {{
                        font-size: 48px;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="bg-particles" id="particles"></div>
            
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
                        <button type="submit">
                            <span>🔐</span> Sign In
                        </button>
                    </form>
                </div>
                
                <div class="credits">
                    Made with ❤️ by <a href="#">@rumoto</a> and <a href="#">@norenaboi</a>
                </div>
            </div>
            
            <script>
                // Generate background particles
                const container = document.getElementById('particles');
                for (let i = 0; i < 25; i++) {{
                    const particle = document.createElement('div');
                    particle.className = 'particle';
                    particle.style.left = Math.random() * 100 + '%';
                    particle.style.animationDelay = Math.random() * 12 + 's';
                    particle.style.animationDuration = (8 + Math.random() * 8) + 's';
                    container.appendChild(particle);
                }}
                
                // Focus effect on input
                const input = document.querySelector('input[type="password"]');
                input.addEventListener('focus', () => {{
                    document.querySelector('.login-container').style.borderColor = 'rgba(59, 130, 246, 0.5)';
                    document.querySelector('.login-container').style.boxShadow = '0 25px 50px -12px rgba(0, 0, 0, 0.5), 0 0 60px rgba(59, 130, 246, 0.2)';
                }});
                input.addEventListener('blur', () => {{
                    document.querySelector('.login-container').style.borderColor = '';
                    document.querySelector('.login-container').style.boxShadow = '';
                }});
            </script>
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

    # Render API Keys (Desktop Table)
    keys_html = ""
    keys_mobile_html = ""
    for key in config["api_keys"]:
        created_date = time.strftime('%Y-%m-%d %H:%M', time.localtime(key.get('created', 0)))
        # Desktop table row
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
        # Mobile card
        keys_mobile_html += f"""
            <div class="key-card" style="background: var(--bg-dark); border: 1px solid var(--border); border-radius: 12px; padding: 16px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <strong style="font-size: 15px; color: var(--text);">{key['name']}</strong>
                    <form action='/delete-key' method='post' style='margin:0;' onsubmit='return confirm("Delete this API key?");'>
                        <input type='hidden' name='key_id' value='{key['key']}'>
                        <button type='submit' class='btn btn-danger' style='padding: 6px 10px; font-size: 12px;'>🗑️</button>
                    </form>
                </div>
                <div style="background: var(--bg-darker); border-radius: 8px; padding: 10px; margin-bottom: 12px; overflow-x: auto;">
                    <code style="font-size: 11px; color: var(--primary); word-break: break-all;">{key['key']}</code>
                </div>
                <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                    <span class="badge">{key.get('rpm', 60)} RPM</span>
                    <span class="badge">{key.get('rpd', 'Unlimited')} RPD</span>
                    <span class="badge" style="background: var(--bg-darker); color: var(--text-muted);">📅 {created_date}</span>
                </div>
            </div>
        """
    
    if not keys_mobile_html:
        keys_mobile_html = '<div style="text-align: center; padding: 30px 20px; color: var(--text-muted);"><p>No API keys yet. Create one below!</p></div>'

    # Render Auth Tokens
    auth_tokens = config.get("auth_tokens", [])
    tokens_html = ""
    if auth_tokens:
        for idx, token in enumerate(auth_tokens):
            token_preview = f"{token[:20]}...{token[-10:]}" if len(token) > 30 else token
            tokens_html += f"""
                <div class="token-item" style="display: flex; align-items: center; justify-content: space-between; padding: 14px 16px; background: var(--bg-dark); border-radius: 12px; margin-bottom: 10px; border: 1px solid var(--border); transition: all 0.2s ease;">
                    <div style="display: flex; align-items: center; gap: 14px; flex: 1; min-width: 0;">
                        <div class="token-index" style="width: 32px; height: 32px; background: linear-gradient(135deg, var(--primary), var(--primary-dark)); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 13px; color: white; flex-shrink: 0;">
                            {idx + 1}
                        </div>
                        <div style="flex: 1; min-width: 0;">
                            <code style="font-family: 'Monaco', 'Consolas', monospace; font-size: 12px; color: var(--text-muted); background: var(--bg-darker); padding: 6px 10px; border-radius: 6px; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{token_preview}</code>
                        </div>
                    </div>
                    <form action='/delete-token' method='post' style='margin: 0; margin-left: 12px;' onsubmit='return confirm("Delete Token #{idx + 1}?");'>
                        <input type='hidden' name='token_index' value='{idx}'>
                        <button type='submit' class='btn btn-danger' style='padding: 8px 12px; font-size: 12px; min-width: auto;'>
                            🗑️
                        </button>
                    </form>
                </div>
            """
    else:
        tokens_html = '<div style="text-align: center; padding: 40px 20px; color: var(--text-muted);"><div style="font-size: 48px; margin-bottom: 16px; opacity: 0.5;">🔑</div><p>No auth tokens configured</p><p style="font-size: 13px;">Click "Add Token" to get started</p></div>'

    # Render Models (limit to first 30 with text output)
    text_models = [m for m in models if m.get('capabilities', {}).get('outputCapabilities', {}).get('text')]
    models_html = ""
    for i, model in enumerate(text_models[:30]):
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
        # Sort by count descending
        sorted_stats = sorted(model_usage_stats.items(), key=lambda x: x[1]["count"] if isinstance(x[1], dict) else x[1], reverse=True)
        
        for model, data in sorted_stats[:30]:
            # Handle legacy int data gracefully
            if isinstance(data, int):
                count = data
                tokens = 0
                last_used = "Unknown"
            else:
                count = data.get("count", 0)
                tokens = data.get("tokens", 0)
                ts = data.get("last_used", 0)
                last_used = time.strftime('%Y-%m-%d %H:%M', time.localtime(ts)) if ts > 0 else "Never"
            
            # Format tokens
            if tokens >= 1_000_000:
                tokens_str = f"{tokens/1_000_000:.1f}M"
            elif tokens >= 1_000:
                tokens_str = f"{tokens/1_000:.1f}K"
            else:
                tokens_str = str(tokens)
                
            stats_html += f"""
                <tr>
                    <td>{model}</td>
                    <td><strong>{count}</strong></td>
                    <td>{tokens_str}</td>
                    <td><small>{last_used}</small></td>
                </tr>
            """
    else:
        stats_html = "<tr><td colspan='4' class='no-data'>No usage data yet</td></tr>"

    # Check token status
    token_status = "✅ Configured" if config.get("auth_token") else "❌ Not Set"
    token_class = "status-good" if config.get("auth_token") else "status-bad"
    
    cf_status = "✅ Configured" if config.get("cf_clearance") else "❌ Not Set"
    cf_class = "status-good" if config.get("cf_clearance") else "status-bad"
    
    # Get generation params
    default_temp = config.get("default_temperature", 0.7)
    default_top_p = config.get("default_top_p", 1.0)
    default_max_tokens = config.get("default_max_tokens", 64000)
    default_pres_pen = config.get("default_presence_penalty", 0.0)
    default_freq_pen = config.get("default_frequency_penalty", 0.0)
    
    # Advanced settings
    chunk_size = config.get("chunk_size", 110000)
    chunk_rotation_limit = config.get("chunk_rotation_limit", 5)
    
    # Get recent activity count (last 24 hours)
    recent_activity_count = sum(1 for timestamps in api_key_usage.values() for t in timestamps if time.time() - t < 86400)
    
    # Generate recent activity HTML from activity_log (per-request tracking)
    recent_activity_html = ""
    if activity_log:
        # Show most recent activities first
        for entry in reversed(activity_log[-10:]):
            tokens = entry.get("tokens", 0)
            if tokens >= 1_000_000:
                tokens_str = f"{tokens/1_000_000:.1f}M"
            elif tokens >= 1_000:
                tokens_str = f"{tokens/1_000:.1f}K"
            else:
                tokens_str = str(tokens)
            
            status_class = "var(--success)" if entry.get("status") == "success" else "var(--error)"
            status_text = "✓ Success" if entry.get("status") == "success" else "✗ Failed"
            status_bg = "var(--success-glow)" if entry.get("status") == "success" else "var(--error-glow)"
                
            recent_activity_html += f"""
                <tr>
                    <td>{entry.get('timestamp', 'N/A')}</td>
                    <td>{entry.get('model', 'Unknown')}</td>
                    <td>{tokens_str}</td>
                    <td><span class="badge" style="background: {status_bg}; color: {status_class};">{status_text}</span></td>
                </tr>
            """
    
    if not recent_activity_html:
        recent_activity_html = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 24px;">No recent activity</td></tr>'

    # Calculate total tokens across all models
    total_tokens = sum(v.get("tokens", 0) if isinstance(v, dict) else 0 for v in model_usage_stats.values())
    if total_tokens >= 1_000_000:
        total_tokens_str = f"{total_tokens/1_000_000:.2f}M"
    elif total_tokens >= 1_000:
        total_tokens_str = f"{total_tokens/1_000:.1f}K"
    else:
        total_tokens_str = str(total_tokens)

    # Prepare chart data safely
    chart_data = {}
    for k, v in model_usage_stats.items():
        if isinstance(v, dict):
            chart_data[k] = v.get("count", 0)
        else:
            chart_data[k] = v
    
    top_models = dict(sorted(chart_data.items(), key=lambda x: x[1], reverse=True)[:30])

    # Prepare variables for template
    total_requests = sum(v.get("count", 0) if isinstance(v, dict) else v for v in model_usage_stats.values())
    api_keys = config.get("api_keys", [])
    uptime_str = get_uptime_string()
    auth_tokens_str = "\n".join(config.get("auth_tokens", []))

    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="mobile-web-app-capable" content="yes">
    <title>LMArena Bridge</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-dark: #020617;
            --bg-darker: #010409;
            --bg-card: #0a1628;
            --bg-card-hover: #0f1d32;
            --bg-hover: #162033;
            --border: #1e3a5f;
            --border-light: #2a4a6f;
            --primary: #3b82f6;
            --primary-light: #60a5fa;
            --primary-dark: #1d4ed8;
            --primary-glow: rgba(59, 130, 246, 0.4);
            --secondary: #6366f1;
            --secondary-glow: rgba(99, 102, 241, 0.3);
            --accent: #0ea5e9;
            --accent-glow: rgba(14, 165, 233, 0.3);
            --success: #10b981;
            --success-glow: rgba(16, 185, 129, 0.3);
            --warning: #f59e0b;
            --warning-glow: rgba(245, 158, 11, 0.3);
            --error: #ef4444;
            --error-glow: rgba(239, 68, 68, 0.3);
            --text-main: #f1f5f9;
            --text-secondary: #cbd5e1;
            --text-muted: #64748b;
            --sidebar-width: 280px;
            --header-height: 72px;
            --transition-fast: 0.15s;
            --transition-normal: 0.25s;
            --transition-slow: 0.4s;
            --ease-bounce: cubic-bezier(0.68, -0.55, 0.265, 1.55);
            --ease-smooth: cubic-bezier(0.4, 0, 0.2, 1);
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }}

        html {{
            scroll-behavior: smooth;
        }}

        body {{
            background: var(--bg-dark);
            background-image: 
                radial-gradient(ellipse at 0% 0%, rgba(59, 130, 246, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at 100% 100%, rgba(99, 102, 241, 0.06) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(14, 165, 233, 0.03) 0%, transparent 70%);
            color: var(--text-main);
            height: 100vh;
            overflow: hidden;
            display: flex;
        }}

        /* Animated Background Particles */
        .bg-particles {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 0;
            overflow: hidden;
        }}

        .particle {{
            position: absolute;
            width: 2px;
            height: 2px;
            background: var(--primary);
            border-radius: 50%;
            opacity: 0;
            animation: float-particle 15s infinite;
        }}

        @keyframes float-particle {{
            0%, 100% {{ opacity: 0; transform: translateY(100vh) scale(0); }}
            10% {{ opacity: 0.6; }}
            90% {{ opacity: 0.6; }}
            100% {{ opacity: 0; transform: translateY(-100vh) scale(1); }}
        }}

        /* Custom Scrollbar */
        ::-webkit-scrollbar {{
            width: 6px;
            height: 6px;
        }}
        ::-webkit-scrollbar-track {{
            background: transparent;
        }}
        ::-webkit-scrollbar-thumb {{
            background: var(--border);
            border-radius: 10px;
            transition: background var(--transition-normal);
        }}
        ::-webkit-scrollbar-thumb:hover {{
            background: var(--primary);
        }}

        /* Glassmorphism Card Effect */
        .glass {{
            background: linear-gradient(135deg, rgba(10, 22, 40, 0.8) 0%, rgba(15, 29, 50, 0.6) 100%);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(59, 130, 246, 0.1);
        }}

        /* Sidebar */
        .sidebar {{
            width: var(--sidebar-width);
            background: linear-gradient(180deg, var(--bg-card) 0%, var(--bg-darker) 100%);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            padding: 24px 20px;
            transition: all var(--transition-slow) var(--ease-smooth);
            z-index: 100;
            position: relative;
            overflow: hidden;
        }}

        .sidebar::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 150px;
            background: radial-gradient(ellipse at 50% 0%, rgba(59, 130, 246, 0.1) 0%, transparent 70%);
            pointer-events: none;
        }}

        .brand {{
            display: flex;
            align-items: center;
            gap: 14px;
            margin-bottom: 40px;
            padding: 12px 16px;
            position: relative;
            z-index: 1;
        }}

        .brand-icon {{
            font-size: 32px;
            filter: drop-shadow(0 0 20px var(--primary-glow));
            animation: pulse-glow 3s ease-in-out infinite;
        }}

        @keyframes pulse-glow {{
            0%, 100% {{ filter: drop-shadow(0 0 15px var(--primary-glow)); transform: scale(1); }}
            50% {{ filter: drop-shadow(0 0 25px var(--primary-glow)); transform: scale(1.05); }}
        }}

        .brand-text {{
            font-size: 22px;
            font-weight: 800;
            background: linear-gradient(135deg, #ffffff 0%, var(--primary-light) 50%, var(--accent) 100%);
            background-size: 200% 200%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            animation: gradient-shift 5s ease infinite;
            letter-spacing: -0.5px;
        }}

        @keyframes gradient-shift {{
            0%, 100% {{ background-position: 0% 50%; }}
            50% {{ background-position: 100% 50%; }}
        }}

        .nav-menu {{
            display: flex;
            flex-direction: column;
            gap: 6px;
            flex: 1;
            position: relative;
            z-index: 1;
        }}

        .nav-item {{
            display: flex;
            align-items: center;
            gap: 14px;
            padding: 14px 18px;
            border-radius: 14px;
            color: var(--text-muted);
            text-decoration: none;
            transition: all var(--transition-normal) var(--ease-smooth);
            cursor: pointer;
            border: 1px solid transparent;
            position: relative;
            overflow: hidden;
            font-weight: 500;
        }}

        .nav-item::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.1), transparent);
            transform: translateX(-100%);
            transition: transform 0.6s ease;
        }}

        .nav-item:hover::before {{
            transform: translateX(100%);
        }}

        .nav-item:hover {{
            background: linear-gradient(135deg, var(--bg-hover) 0%, rgba(59, 130, 246, 0.08) 100%);
            color: var(--text-main);
            transform: translateX(4px);
            border-color: rgba(59, 130, 246, 0.15);
        }}

        .nav-item.active {{
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.15) 0%, rgba(99, 102, 241, 0.1) 100%);
            color: var(--primary-light);
            border-color: rgba(59, 130, 246, 0.3);
            box-shadow: 
                0 0 20px rgba(59, 130, 246, 0.15),
                inset 0 0 20px rgba(59, 130, 246, 0.05);
        }}

        .nav-item.active .nav-icon {{
            transform: scale(1.1);
            filter: drop-shadow(0 0 8px var(--primary-glow));
        }}

        .nav-icon {{
            font-size: 20px;
            transition: all var(--transition-normal) var(--ease-bounce);
        }}

        .nav-item:hover .nav-icon {{
            transform: scale(1.15) rotate(-5deg);
        }}

        .user-profile {{
            margin-top: auto;
            padding: 16px;
            background: linear-gradient(135deg, var(--bg-hover) 0%, rgba(59, 130, 246, 0.05) 100%);
            border-radius: 16px;
            display: flex;
            align-items: center;
            gap: 14px;
            border: 1px solid var(--border);
            transition: all var(--transition-normal) var(--ease-smooth);
            position: relative;
            z-index: 1;
        }}

        .user-profile:hover {{
            border-color: var(--primary);
            box-shadow: 0 0 25px rgba(59, 130, 246, 0.15);
            transform: translateY(-2px);
        }}

        .user-avatar {{
            width: 42px;
            height: 42px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 50%, var(--accent) 100%);
            background-size: 200% 200%;
            animation: gradient-shift 4s ease infinite;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            color: white;
            font-size: 16px;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
        }}

        .logout-btn {{
            color: var(--text-muted);
            text-decoration: none;
            padding: 8px;
            border-radius: 8px;
            transition: all var(--transition-fast);
            font-size: 18px;
        }}

        .logout-btn:hover {{
            color: var(--error);
            background: rgba(239, 68, 68, 0.1);
            transform: scale(1.1);
        }}

        /* Main Content */
        .main-content {{
            flex: 1;
            display: flex;
            flex-direction: column;
            height: 100vh;
            overflow: hidden;
            position: relative;
            z-index: 1;
        }}

        .header {{
            height: var(--header-height);
            padding: 0 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border);
            background: linear-gradient(180deg, rgba(10, 22, 40, 0.95) 0%, rgba(2, 6, 23, 0.9) 100%);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            position: sticky;
            top: 0;
            z-index: 40;
        }}

        .page-title {{
            font-size: 26px;
            font-weight: 700;
            color: var(--text-main);
            letter-spacing: -0.5px;
            position: relative;
        }}

        .page-title::after {{
            content: '';
            position: absolute;
            bottom: -4px;
            left: 0;
            width: 40px;
            height: 3px;
            background: linear-gradient(90deg, var(--primary), transparent);
            border-radius: 2px;
        }}

        .version-badge {{
            padding: 6px 14px;
            background: linear-gradient(135deg, var(--bg-hover) 0%, rgba(59, 130, 246, 0.1) 100%);
            border: 1px solid var(--border);
            border-radius: 20px;
            font-size: 13px;
            color: var(--text-secondary);
            font-weight: 500;
            transition: all var(--transition-normal);
        }}

        .version-badge:hover {{
            border-color: var(--primary);
            color: var(--primary-light);
            transform: scale(1.05);
        }}

        .content-scroll {{
            flex: 1;
            overflow-y: auto;
            padding: 32px;
            scroll-behavior: smooth;
            -webkit-overflow-scrolling: touch;
        }}

        .section {{
            display: none;
            animation: section-enter 0.5s var(--ease-smooth);
        }}

        .section.active {{
            display: block;
        }}

        @keyframes section-enter {{
            from {{ 
                opacity: 0; 
                transform: translateY(30px) scale(0.98);
                filter: blur(4px);
            }}
            to {{ 
                opacity: 1; 
                transform: translateY(0) scale(1);
                filter: blur(0);
            }}
        }}

        /* Grid Layouts */
        .grid-2 {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
            gap: 24px;
            margin-bottom: 24px;
        }}

        .grid-4 {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 28px;
        }}

        /* Cards - Enhanced with Glass Effect */
        .card {{
            background: linear-gradient(145deg, var(--bg-card) 0%, rgba(15, 29, 50, 0.8) 100%);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 24px;
            transition: all var(--transition-normal) var(--ease-smooth);
            position: relative;
            overflow: hidden;
        }}

        .card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.3), transparent);
        }}

        .card:hover {{
            transform: translateY(-4px);
            box-shadow: 
                0 20px 40px -15px rgba(0, 0, 0, 0.5),
                0 0 30px rgba(59, 130, 246, 0.1);
            border-color: rgba(59, 130, 246, 0.3);
        }}

        /* Stat Cards - Premium Design */
        .stat-card {{
            display: flex;
            flex-direction: column;
            gap: 12px;
            position: relative;
            overflow: hidden;
        }}

        .stat-card::after {{
            content: '';
            position: absolute;
            bottom: 0;
            right: 0;
            width: 120px;
            height: 120px;
            background: radial-gradient(circle, rgba(59, 130, 246, 0.08) 0%, transparent 70%);
            transform: translate(30%, 30%);
            transition: all var(--transition-slow);
        }}

        .stat-card:hover::after {{
            transform: translate(20%, 20%) scale(1.2);
            background: radial-gradient(circle, rgba(59, 130, 246, 0.15) 0%, transparent 70%);
        }}

        .stat-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            color: var(--text-muted);
            font-size: 13px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .stat-icon {{
            font-size: 24px;
            filter: grayscale(0.3);
            transition: all var(--transition-normal);
        }}

        .stat-card:hover .stat-icon {{
            filter: grayscale(0);
            transform: scale(1.2) rotate(5deg);
        }}

        .stat-value {{
            font-size: 36px;
            font-weight: 800;
            color: var(--text-main);
            background: linear-gradient(135deg, var(--text-main) 0%, var(--primary-light) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            line-height: 1.1;
        }}

        .stat-trend {{
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            background: rgba(16, 185, 129, 0.1);
            border-radius: 20px;
            width: fit-content;
            font-weight: 500;
        }}

        .trend-up {{ 
            color: var(--success);
            background: rgba(16, 185, 129, 0.1);
        }}
        .trend-down {{ 
            color: var(--error);
            background: rgba(239, 68, 68, 0.1);
        }}

        /* Tables - Enhanced */
        .table-container {{
            overflow-x: auto;
            border-radius: 12px;
        }}

        table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
        }}

        th {{
            text-align: left;
            padding: 16px 20px;
            color: var(--text-muted);
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid var(--border);
            background: rgba(15, 29, 50, 0.5);
        }}

        td {{
            padding: 16px 20px;
            border-bottom: 1px solid rgba(30, 58, 95, 0.5);
            color: var(--text-main);
            transition: all var(--transition-fast);
        }}

        tr {{
            transition: all var(--transition-fast);
        }}

        tbody tr:hover {{
            background: linear-gradient(90deg, rgba(59, 130, 246, 0.05) 0%, transparent 100%);
        }}

        tbody tr:hover td {{
            color: var(--primary-light);
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        /* Forms - Premium Inputs */
        .form-group {{
            margin-bottom: 24px;
        }}

        .form-label {{
            display: block;
            margin-bottom: 10px;
            color: var(--text-secondary);
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .form-input {{
            width: 100%;
            padding: 14px 18px;
            background: linear-gradient(135deg, var(--bg-dark) 0%, rgba(15, 29, 50, 0.5) 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--text-main);
            font-size: 14px;
            transition: all var(--transition-normal) var(--ease-smooth);
        }}

        .form-input:focus {{
            outline: none;
            border-color: var(--primary);
            box-shadow: 
                0 0 0 3px rgba(59, 130, 246, 0.15),
                0 0 20px rgba(59, 130, 246, 0.1);
            transform: translateY(-1px);
        }}

        .form-input::placeholder {{
            color: var(--text-muted);
        }}

        textarea.form-input {{
            resize: vertical;
            min-height: 120px;
            font-family: 'SF Mono', 'Fira Code', 'Monaco', monospace;
            font-size: 13px;
            line-height: 1.6;
        }}

        /* Select/Dropdown Styling */
        select.form-input {{
            appearance: none;
            -webkit-appearance: none;
            -moz-appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%2360a5fa' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 14px center;
            padding-right: 40px;
            cursor: pointer;
        }}

        select.form-input option {{
            background: var(--bg-card);
            color: var(--text-main);
            padding: 12px;
        }}

        select.form-input option:hover,
        select.form-input option:focus,
        select.form-input option:checked {{
            background: var(--primary);
            color: white;
        }}

        /* Buttons - Premium Design with Touch Support */
        .btn {{
            padding: 14px 28px;
            border-radius: 12px;
            border: none;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            transition: all var(--transition-normal) var(--ease-smooth);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            position: relative;
            overflow: hidden;
            text-decoration: none;
            -webkit-tap-highlight-color: transparent;
            touch-action: manipulation;
            user-select: none;
            -webkit-user-select: none;
        }}

        .btn::before {{
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s ease;
        }}

        .btn:hover::before {{
            left: 100%;
        }}

        .btn-primary {{
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            box-shadow: 
                0 4px 15px rgba(59, 130, 246, 0.3),
                inset 0 1px 0 rgba(255,255,255,0.1);
        }}

        .btn-primary:hover {{
            transform: translateY(-2px) scale(1.02);
            box-shadow: 
                0 8px 25px rgba(59, 130, 246, 0.4),
                0 0 30px rgba(59, 130, 246, 0.2);
        }}

        .btn-primary:active {{
            transform: translateY(0) scale(0.98);
        }}

        .btn-danger {{
            background: linear-gradient(135deg, var(--error) 0%, #dc2626 100%);
            color: white;
            padding: 10px 18px;
            font-size: 13px;
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.25);
        }}

        .btn-danger:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(239, 68, 68, 0.35);
        }}

        .btn-secondary {{
            background: linear-gradient(135deg, var(--bg-hover) 0%, var(--bg-card) 100%);
            color: var(--text-main);
            border: 1px solid var(--border);
        }}

        .btn-secondary:hover {{
            border-color: var(--primary);
            color: var(--primary-light);
            transform: translateY(-2px);
        }}

        /* Badges */
        .badge {{
            display: inline-flex;
            align-items: center;
            padding: 6px 12px;
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.15) 0%, rgba(99, 102, 241, 0.1) 100%);
            border: 1px solid rgba(59, 130, 246, 0.2);
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            color: var(--primary-light);
            transition: all var(--transition-fast);
        }}

        .badge:hover {{
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.25) 0%, rgba(99, 102, 241, 0.15) 100%);
            transform: scale(1.05);
        }}

        /* API Key Code Display */
        .api-key-code {{
            font-family: 'SF Mono', 'Fira Code', monospace;
            font-size: 12px;
            padding: 8px 14px;
            background: linear-gradient(135deg, var(--bg-dark) 0%, rgba(15, 29, 50, 0.8) 100%);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--accent);
            word-break: break-all;
            display: inline-block;
            transition: all var(--transition-fast);
        }}

        .api-key-code:hover {{
            border-color: var(--accent);
            box-shadow: 0 0 15px rgba(14, 165, 233, 0.2);
        }}

        /* Section Headers */
        .section-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
        }}

        .section-header h3 {{
            font-size: 18px;
            font-weight: 700;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .section-header h3::before {{
            content: '';
            width: 4px;
            height: 20px;
            background: linear-gradient(180deg, var(--primary), var(--accent));
            border-radius: 2px;
        }}

        /* Progress Bars */
        .progress-container {{
            margin: 20px 0;
        }}

        .progress-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            font-size: 13px;
            color: var(--text-muted);
            font-weight: 500;
        }}

        .progress-bar-bg {{
            height: 8px;
            background: var(--bg-dark);
            border-radius: 10px;
            overflow: hidden;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.3);
        }}

        .progress-bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--accent));
            border-radius: 10px;
            transition: width 0.5s var(--ease-smooth);
            position: relative;
        }}

        .progress-bar-fill::after {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            animation: shimmer 2s infinite;
        }}

        @keyframes shimmer {{
            0% {{ transform: translateX(-100%); }}
            100% {{ transform: translateX(100%); }}
        }}

        /* Collection Badge */
        .collection-badge {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 20px;
            border-radius: 30px;
            font-size: 14px;
            font-weight: 600;
            transition: all var(--transition-normal);
        }}

        .collection-badge.idle {{
            background: var(--bg-dark);
            color: var(--text-muted);
            border: 1px solid var(--border);
        }}

        .collection-badge.running {{
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(14, 165, 233, 0.2));
            color: var(--primary-light);
            border: 1px solid rgba(59, 130, 246, 0.3);
            animation: pulse-badge 2s ease-in-out infinite;
        }}

        .collection-badge.done {{
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.2), rgba(52, 211, 153, 0.15));
            color: var(--success);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}

        @keyframes pulse-badge {{
            0%, 100% {{ box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.4); }}
            50% {{ box-shadow: 0 0 0 10px rgba(59, 130, 246, 0); }}
        }}

        /* Logs Container */
        .logs-container {{
            background: linear-gradient(180deg, #000408 0%, #010610 100%);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 20px;
            font-family: 'SF Mono', 'Fira Code', 'Monaco', monospace;
            font-size: 12px;
            line-height: 1.8;
            overflow-y: auto;
            scroll-behavior: smooth;
        }}

        .log-entry {{
            padding: 4px 0;
            border-left: 2px solid transparent;
            padding-left: 12px;
            margin-left: -12px;
            transition: all var(--transition-fast);
        }}

        .log-entry:hover {{
            background: rgba(59, 130, 246, 0.05);
            border-left-color: var(--primary);
        }}

        .log-timestamp {{
            color: var(--text-muted);
        }}

        .log-level {{
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 10px;
            text-transform: uppercase;
        }}

        .log-level-info {{ color: var(--primary); background: rgba(59, 130, 246, 0.1); }}
        .log-level-success {{ color: var(--success); background: rgba(16, 185, 129, 0.1); }}
        .log-level-warn {{ color: var(--warning); background: rgba(245, 158, 11, 0.1); }}
        .log-level-error {{ color: var(--error); background: rgba(239, 68, 68, 0.1); }}
        .log-level-debug {{ color: var(--text-muted); background: rgba(100, 116, 139, 0.1); }}

        .log-message {{
            color: var(--text-secondary);
        }}

        /* System Info Panel */
        .system-info {{
            background: linear-gradient(135deg, var(--bg-dark) 0%, rgba(10, 22, 40, 0.8) 100%);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 20px;
        }}

        .system-info-row {{
            display: flex;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid rgba(30, 58, 95, 0.3);
        }}

        .system-info-row:last-child {{
            border-bottom: none;
        }}

        .system-info-label {{
            color: var(--text-muted);
            font-size: 13px;
            font-weight: 500;
        }}

        .system-info-value {{
            color: var(--primary-light);
            font-family: 'SF Mono', monospace;
            font-size: 13px;
            font-weight: 600;
        }}

        /* No Data State */
        .no-data {{
            text-align: center;
            padding: 40px 20px;
            color: var(--text-muted);
            font-size: 14px;
        }}

        .no-data-icon {{
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }}

        /* Mobile Toggle */
        .mobile-toggle {{
            display: none;
            font-size: 24px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--text-main);
            cursor: pointer;
            padding: 12px 16px;
            transition: all var(--transition-fast);
            -webkit-tap-highlight-color: transparent;
            touch-action: manipulation;
            user-select: none;
        }}

        .mobile-toggle:hover, .mobile-toggle:active {{
            background: var(--bg-hover);
            border-color: var(--primary);
            color: var(--primary-light);
        }}

        /* Overlay for mobile sidebar */
        .sidebar-overlay {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(4px);
            z-index: 90;
            opacity: 0;
            visibility: hidden;
            pointer-events: none;
            transition: opacity var(--transition-normal), visibility var(--transition-normal);
            -webkit-tap-highlight-color: transparent;
            touch-action: manipulation;
        }}

        .sidebar-overlay.active {{
            opacity: 1;
            visibility: visible;
            pointer-events: auto;
        }}

        /* Modal Overlay */
        .modal-overlay {{
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(8px);
            z-index: 1000;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            animation: fadeIn 0.2s ease;
        }}

        .modal-content {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 20px;
            width: 100%;
            max-width: 500px;
            max-height: 90vh;
            overflow-y: auto;
            animation: slideUp 0.3s ease;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }}

        .modal-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
        }}

        .modal-header h3 {{
            margin: 0;
            font-size: 18px;
            font-weight: 600;
            color: var(--text-main);
        }}

        .modal-close {{
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 28px;
            cursor: pointer;
            padding: 0;
            line-height: 1;
            transition: all 0.2s ease;
        }}

        .modal-close:hover {{
            color: var(--danger);
            transform: scale(1.1);
        }}

        .modal-content form {{
            padding: 24px;
        }}

        @keyframes slideUp {{
            from {{
                opacity: 0;
                transform: translateY(20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}

        /* Token List Styles */
        .token-list {{
            scrollbar-width: thin;
            scrollbar-color: var(--border) transparent;
        }}

        .token-list::-webkit-scrollbar {{
            width: 6px;
        }}

        .token-list::-webkit-scrollbar-track {{
            background: transparent;
        }}

        .token-list::-webkit-scrollbar-thumb {{
            background: var(--border);
            border-radius: 3px;
        }}

        .token-list::-webkit-scrollbar-thumb:hover {{
            background: var(--border-light);
        }}

        .token-item:hover {{
            border-color: var(--primary);
            background: var(--bg-hover);
        }}

        /* Avatar Option Buttons */
        .avatar-option {{
            width: 44px;
            height: 44px;
            font-size: 22px;
            background: var(--bg-dark);
            border: 2px solid var(--border);
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
        }}

        .avatar-option:hover {{
            border-color: var(--primary);
            background: var(--bg-hover);
            transform: scale(1.1);
        }}

        .avatar-option:active {{
            transform: scale(0.95);
        }}

        /* Ripple Effect */
        .ripple {{
            position: absolute;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.3);
            transform: scale(0);
            animation: ripple-effect 0.6s ease-out;
            pointer-events: none;
        }}

        @keyframes ripple-effect {{
            to {{
                transform: scale(4);
                opacity: 0;
            }}
        }}

        /* Tooltip */
        .tooltip {{
            position: relative;
        }}

        .tooltip::after {{
            content: attr(data-tooltip);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%) translateY(-8px);
            padding: 8px 14px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 12px;
            color: var(--text-main);
            white-space: nowrap;
            opacity: 0;
            visibility: hidden;
            transition: all var(--transition-fast);
            z-index: 100;
        }}

        .tooltip:hover::after {{
            opacity: 1;
            visibility: visible;
            transform: translateX(-50%) translateY(-12px);
        }}

        /* Chart Container */
        .chart-container {{
            position: relative;
            height: 300px;
            padding: 10px;
        }}

        /* Responsive visibility helpers */
        .desktop-only {{
            display: block;
        }}
        .mobile-only {{
            display: none !important;
        }}

        /* Responsive Design */
        @media (max-width: 1200px) {{
            .grid-4 {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}

        @media (max-width: 992px) {{
            .grid-2 {{
                grid-template-columns: 1fr;
            }}
        }}

        @media (max-width: 768px) {{
            /* Show/hide for mobile */
            .desktop-only {{
                display: none !important;
            }}
            .mobile-only {{
                display: block !important;
            }}
            
            /* Disable hover effects on touch devices */
            * {{
                -webkit-tap-highlight-color: transparent;
            }}
            
            .sidebar {{
                position: fixed;
                left: -100%;
                width: 85%;
                max-width: 300px;
                height: 100%;
                box-shadow: 20px 0 60px rgba(0,0,0,0.6);
                transition: left var(--transition-normal) var(--ease-smooth);
                z-index: 100;
                overflow-y: auto;
                -webkit-overflow-scrolling: touch;
            }}
            
            .sidebar.open {{
                left: 0;
            }}

            .sidebar-overlay {{
                display: block;
                pointer-events: none;
            }}
            
            .sidebar-overlay.active {{
                pointer-events: auto;
            }}

            .mobile-toggle {{
                display: flex;
                align-items: center;
                justify-content: center;
            }}

            .header {{
                padding: 0 16px;
            }}

            .page-title {{
                font-size: 20px;
            }}

            .content-scroll {{
                padding: 16px;
                padding-bottom: 100px; /* Extra space for bottom elements */
            }}

            .grid-4 {{
                grid-template-columns: 1fr;
                gap: 16px;
            }}

            .grid-2 {{
                grid-template-columns: 1fr;
            }}

            .card {{
                padding: 20px;
            }}

            .stat-value {{
                font-size: 28px;
            }}

            /* Mobile-friendly buttons */
            .btn {{
                padding: 14px 20px;
                min-height: 48px; /* Touch-friendly minimum */
                width: 100%;
                justify-content: center;
                touch-action: manipulation;
                user-select: none;
            }}
            
            /* Navigation items need bigger touch targets */
            .nav-item {{
                padding: 18px 20px;
                min-height: 56px;
                touch-action: manipulation;
            }}

            table {{
                font-size: 13px;
            }}

            th, td {{
                padding: 12px 10px;
            }}

            .chart-container {{
                height: 250px;
            }}
            
            /* Fix z-index stacking */
            .modal-overlay {{
                z-index: 200;
            }}
            
            .modal-content {{
                z-index: 201;
            }}
        }}

        @media (max-width: 480px) {{
            .grid-4 {{
                gap: 12px;
            }}

            .card {{
                padding: 16px;
                border-radius: 16px;
            }}

            .section-header {{
                flex-direction: column;
                align-items: flex-start !important;
                gap: 12px;
            }}

            .section-header h3 {{
                font-size: 16px;
            }}

            .section-header > div {{
                width: 100%;
                flex-direction: column;
                gap: 10px;
            }}

            .section-header select, .section-header button {{
                width: 100% !important;
                min-width: unset !important;
                min-height: 48px;
            }}

            .stat-card {{
                padding: 16px;
            }}

            .stat-value {{
                font-size: 24px;
            }}

            .api-key-code {{
                font-size: 10px;
                padding: 6px 10px;
                word-break: break-all;
            }}

            .badge {{
                font-size: 10px;
                padding: 4px 8px;
            }}

            /* Mobile table improvements */
            .table-container {{
                margin: 0 -16px;
                padding: 0 16px;
                overflow-x: auto;
                -webkit-overflow-scrolling: touch;
            }}

            table {{
                min-width: 500px;
            }}

            th, td {{
                padding: 10px 8px;
                font-size: 12px;
            }}

            /* Mobile form improvements */
            .form-group {{
                margin-bottom: 16px;
            }}

            .form-input, input, select, textarea {{
                padding: 14px 16px;
                font-size: 16px !important; /* Prevents iOS zoom on focus */
                min-height: 48px;
                touch-action: manipulation;
            }}
            
            /* Fix select dropdowns on mobile */
            select {{
                -webkit-appearance: none;
                appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%2394a3b8' viewBox='0 0 16 16'%3E%3Cpath d='M8 11L3 6h10l-5 5z'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: right 12px center;
                padding-right: 36px;
            }}

            /* Mobile nav improvements */
            .nav-item {{
                padding: 18px 20px;
                min-height: 56px;
                display: flex;
                align-items: center;
            }}

            .nav-icon {{
                font-size: 22px;
            }}

            /* Mobile user profile */
            .user-profile {{
                padding: 16px;
            }}

            /* Modal mobile fixes */
            .modal-overlay {{
                padding: 12px;
                align-items: flex-start;
                padding-top: 60px;
            }}
            
            .modal-content {{
                margin: 0;
                max-height: calc(100vh - 80px);
                width: 100%;
                border-radius: 16px;
            }}
            
            .modal-header {{
                padding: 16px 20px;
                position: sticky;
                top: 0;
                background: var(--bg-card);
                z-index: 10;
            }}
            
            .modal-body {{
                padding: 16px 20px;
            }}
            
            .modal-close {{
                min-width: 44px;
                min-height: 44px;
                display: flex;
                align-items: center;
                justify-content: center;
            }}

            /* Chart smaller on mobile */
            .chart-container {{
                height: 200px;
            }}

            /* Leaderboard table mobile fix */
            #leaderboard-table {{
                min-width: 650px;
            }}

            /* Token list mobile */
            .token-item {{
                flex-direction: column;
                gap: 12px;
                align-items: stretch !important;
                padding: 16px;
            }}

            .token-item > div:first-child {{
                flex-direction: column;
                gap: 8px;
            }}

            .token-item form {{
                margin-left: 0 !important;
                align-self: stretch;
            }}
            
            .token-item form button {{
                width: 100%;
            }}
            
            /* Mobile-friendly action buttons */
            .btn-danger, .btn-primary, .btn-secondary {{
                min-height: 48px;
                padding: 12px 16px;
            }}
            
            /* Create API Key form mobile */
            .create-key-form > div {{
                grid-template-columns: 1fr !important;
            }}
            
            /* Fix clickable areas */
            a, button, [onclick], .clickable {{
                min-height: 44px;
                min-width: 44px;
            }}
            
            /* Better touch feedback */
            button:active, .btn:active, .nav-item:active {{
                transform: scale(0.98);
                opacity: 0.9;
            }}
        }}

        /* Extra small mobile */
        @media (max-width: 360px) {{
            .brand-text {{
                font-size: 16px;
            }}

            .stat-value {{
                font-size: 18px;
            }}

            .page-title {{
                font-size: 16px;
            }}
            
            .card {{
                padding: 14px;
            }}
            
            .section-header h3 {{
                font-size: 14px;
            }}
            
            .btn {{
                padding: 12px 16px;
                font-size: 13px;
            }}
            
            .nav-item {{
                padding: 14px 16px;
            }}
        }}
        
        /* Touch device optimizations */
        @media (hover: none) and (pointer: coarse) {{
            /* Remove hover effects on touch devices */
            .btn:hover {{
                transform: none;
            }}
            
            .btn:active {{
                transform: scale(0.97);
            }}
            
            .nav-item:hover {{
                background: transparent;
            }}
            
            .nav-item:active {{
                background: var(--bg-hover);
            }}
            
            /* Larger touch targets */
            .btn, button, a, .nav-item, select, input {{
                min-height: 44px;
            }}
            
            /* Disable animations that can cause jank */
            .card {{
                transition: none;
            }}
            
            tbody tr:hover {{
                transform: none;
            }}
        }}

        /* Loading Animation */
        .loading-dots {{
            display: inline-flex;
            gap: 4px;
        }}

        .loading-dots span {{
            width: 6px;
            height: 6px;
            background: var(--primary);
            border-radius: 50%;
            animation: bounce-dot 1.4s ease-in-out infinite;
        }}

        .loading-dots span:nth-child(1) {{ animation-delay: 0s; }}
        .loading-dots span:nth-child(2) {{ animation-delay: 0.2s; }}
        .loading-dots span:nth-child(3) {{ animation-delay: 0.4s; }}

        @keyframes bounce-dot {{
            0%, 80%, 100% {{ transform: scale(0.6); opacity: 0.5; }}
            40% {{ transform: scale(1); opacity: 1; }}
        }}

        /* Skeleton Loading */
        .skeleton {{
            background: linear-gradient(90deg, var(--bg-hover) 25%, var(--bg-card) 50%, var(--bg-hover) 75%);
            background-size: 200% 100%;
            animation: skeleton-loading 1.5s infinite;
            border-radius: 8px;
        }}

        @keyframes skeleton-loading {{
            0% {{ background-position: 200% 0; }}
            100% {{ background-position: -200% 0; }}
        }}

        /* Fade In Animation for leaderboard rows */
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateX(-10px); }}
            to {{ opacity: 1; transform: translateX(0); }}
        }}

        /* Leaderboard specific styles */
        #leaderboard-table tbody tr:hover {{
            background: var(--bg-hover);
        }}

        #leaderboard-table tbody tr {{
            transition: background 0.2s ease;
        }}

        /* Focus Visible for Accessibility */
        *:focus-visible {{
            outline: 2px solid var(--primary);
            outline-offset: 2px;
        }}

        /* Selection Color */
        ::selection {{
            background: rgba(59, 130, 246, 0.3);
            color: var(--text-main);
        }}
    </style>
</head>
<body>
    <!-- Animated Background Particles -->
    <div class="bg-particles" id="particles"></div>
    
    <!-- Mobile Sidebar Overlay -->
    <div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>

    <!-- Sidebar -->
    <aside class="sidebar" id="sidebar">
        <div class="brand">
            <span class="brand-icon">🚀</span>
            <span class="brand-text">LMArena Bridge</span>
        </div>
        
        <nav class="nav-menu">
            <div class="nav-item active" onclick="showSection('dashboard')" data-section="dashboard">
                <span class="nav-icon">📊</span>
                <span>Dashboard</span>
            </div>
            <div class="nav-item" onclick="showSection('models')" data-section="models">
                <span class="nav-icon">🤖</span>
                <span>Models</span>
            </div>
            <div class="nav-item" onclick="showSection('leaderboard')" data-section="leaderboard">
                <span class="nav-icon">🏆</span>
                <span>Leaderboard</span>
            </div>
            <div class="nav-item" onclick="showSection('keys')" data-section="keys">
                <span class="nav-icon">🔑</span>
                <span>API Keys</span>
            </div>
            <div class="nav-item" onclick="showSection('auth')" data-section="auth">
                <span class="nav-icon">🛡️</span>
                <span>Auth Tokens</span>
            </div>
            <div class="nav-item" onclick="showSection('logs')" data-section="logs">
                <span class="nav-icon">📜</span>
                <span>Live Logs</span>
            </div>
            <div class="nav-item" onclick="showSection('settings')" data-section="settings">
                <span class="nav-icon">⚙️</span>
                <span>Settings</span>
            </div>
            <div class="nav-item" onclick="showSection('profile')" data-section="profile">
                <span class="nav-icon">👤</span>
                <span>Profile</span>
            </div>
        </nav>

        <div class="user-profile" onclick="showSection('profile')" style="cursor: pointer;">
            <div class="user-avatar">{config.get('profile_avatar', '👤')}</div>
            <div style="flex: 1; overflow: hidden;">
                <div style="font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--text-main);">{config.get('profile_name', 'Admin User')}</div>
                <div style="font-size: 12px; color: var(--success); display: flex; align-items: center; gap: 6px;">
                    <span style="width: 6px; height: 6px; background: var(--success); border-radius: 50%; animation: pulse-glow 2s infinite;"></span>
                    Online
                </div>
            </div>
            <a href="/logout" class="logout-btn tooltip" data-tooltip="Sign Out" onclick="event.stopPropagation();">🚪</a>
        </div>
    </aside>

    <!-- Main Content -->
    <main class="main-content">
        <header class="header">
            <div style="display: flex; align-items: center; gap: 16px;">
                <button class="mobile-toggle" onclick="toggleSidebar()">☰</button>
                <h1 class="page-title" id="page-title">Dashboard</h1>
            </div>
            <div style="display: flex; gap: 12px; align-items: center;">
                <span class="version-badge">v4.0.0</span>
            </div>
        </header>

        <div class="content-scroll">
            <!-- Dashboard Section -->
            <div id="section-dashboard" class="section active">
                <div class="grid-4">
                    <div class="card stat-card" style="animation-delay: 0s;">
                        <div class="stat-header">
                            <span>Total Requests</span>
                            <span class="stat-icon">📈</span>
                        </div>
                        <div class="stat-value">{total_requests:,}</div>
                        <div class="stat-trend trend-up">
                            <span>✨ All time</span>
                        </div>
                    </div>
                    <div class="card stat-card" style="animation-delay: 0.1s;">
                        <div class="stat-header">
                            <span>Total Tokens</span>
                            <span class="stat-icon">🔢</span>
                        </div>
                        <div class="stat-value">{total_tokens_str}</div>
                        <div class="stat-trend">
                            <span>💬 Generated</span>
                        </div>
                    </div>
                    <div class="card stat-card" style="animation-delay: 0.2s;">
                        <div class="stat-header">
                            <span>Active Models</span>
                            <span class="stat-icon">🤖</span>
                        </div>
                        <div class="stat-value">{len(model_usage_stats)}</div>
                        <div class="stat-trend">
                            <span>🟢 In Use</span>
                        </div>
                    </div>
                    <div class="card stat-card" style="animation-delay: 0.3s;">
                        <div class="stat-header">
                            <span>Uptime</span>
                            <span class="stat-icon">⏱️</span>
                        </div>
                        <div class="stat-value" id="uptime-value">{uptime_str}</div>
                        <div class="stat-trend trend-up">
                            <span>🚀 Running</span>
                        </div>
                    </div>
                </div>
                <div class="grid-2">
                    <div class="card">
                        <div class="section-header">
                            <h3>📊 Model Distribution</h3>
                        </div>
                        <div class="chart-container">
                            <canvas id="modelPieChart"></canvas>
                        </div>
                    </div>
                    <div class="card" onclick="showSection('leaderboard'); loadLeaderboard();" style="cursor: pointer; transition: all 0.3s ease;" onmouseover="this.style.borderColor='var(--primary)'; this.style.transform='translateY(-4px)';" onmouseout="this.style.borderColor='var(--border)'; this.style.transform='translateY(0)';">
                        <div class="section-header" style="justify-content: space-between;">
                            <h3>🏆 LMArena Top Models</h3>
                            <span style="font-size: 13px; color: var(--primary-light); display: flex; align-items: center; gap: 6px;">View Full Rankings <span style="font-size: 16px;">→</span></span>
                        </div>
                        <div style="padding: 8px 0;" id="top-models-preview">
                            <div style="display: flex; flex-direction: column; gap: 8px;" id="top-models-list">
                                <!-- Dynamically populated -->
                            </div>
                        </div>
                        <div style="text-align: center; padding-top: 12px; border-top: 1px solid var(--border); margin-top: 8px;">
                            <span style="font-size: 12px; color: var(--text-muted);">Click to see full LMArena rankings →</span>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="section-header">
                        <h3>⚡ Recent Activity</h3>
                    </div>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Model</th>
                                    <th>Tokens</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {recent_activity_html}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Models Section -->
            <div id="section-models" class="section">
                <div class="card">
                    <div class="section-header">
                        <h3>🤖 Model Usage Statistics</h3>
                    </div>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Model</th>
                                    <th>Requests</th>
                                    <th>Tokens</th>
                                    <th>Last Used</th>
                                </tr>
                            </thead>
                            <tbody>
                                {stats_html}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Leaderboard Section -->
            <div id="section-leaderboard" class="section">
                <div class="card">
                    <div class="section-header" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
                        <h3>🏆 LMArena Text Leaderboard</h3>
                        <div style="display: flex; gap: 12px; align-items: center;">
                            <span id="leaderboard-updated" style="font-size: 12px; color: var(--text-muted);"></span>
                            <button class="btn btn-secondary" onclick="refreshLeaderboard()" style="padding: 10px 16px;">
                                🔄 Refresh
                            </button>
                        </div>
                    </div>
                    <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
                        📊 Rankings fetched using browser automation (bypasses Cloudflare). Click Refresh to fetch live data from <a href="https://lmarena.ai/leaderboard/text" target="_blank" style="color: var(--primary-light);">lmarena.ai</a>
                    </p>
                    <div id="leaderboard-loading" style="display: none; text-align: center; padding: 60px 20px;">
                        <div class="loading-dots"><span></span><span></span><span></span></div>
                        <p style="margin-top: 16px; color: var(--text-muted);">Loading leaderboard data...</p>
                    </div>
                    <div id="leaderboard-error" style="display: none; text-align: center; padding: 60px 20px; color: var(--error);">
                        <div style="font-size: 48px; margin-bottom: 16px;">⚠️</div>
                        <p>Failed to load leaderboard data</p>
                        <button class="btn btn-primary" onclick="loadLeaderboard()" style="margin-top: 16px;">Try Again</button>
                    </div>
                    <div class="table-container" id="leaderboard-table-container" style="overflow-x: auto;">
                        <table id="leaderboard-table" style="min-width: 700px;">
                            <thead>
                                <tr>
                                    <th style="width: 60px; text-align: center;">Rank</th>
                                    <th style="width: 120px;">Provider</th>
                                    <th>Model</th>
                                    <th style="width: 80px; text-align: center;">ELO</th>
                                    <th style="width: 70px; text-align: center;">95% CI</th>
                                    <th style="width: 80px; text-align: center;">Votes</th>
                                </tr>
                            </thead>
                            <tbody id="leaderboard-body">
                                <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 40px;">Click Refresh to fetch live rankings from LMArena</td></tr>
                            </tbody>
                        </table>
                    </div>
                    <div style="margin-top: 20px; padding: 16px; background: var(--bg-dark); border-radius: 12px; font-size: 13px; color: var(--text-muted);">
                        <strong>📊 Data Source:</strong> <a href="https://lmarena.ai/leaderboard/text" target="_blank" style="color: var(--primary-light);">lmarena.ai/leaderboard/text</a>
                        <span style="margin-left: 16px;">• Rankings based on human preference votes</span>
                    </div>
                </div>
            </div>

            <!-- Keys Section -->
            <div id="section-keys" class="section">
                <div class="card">
                    <div class="section-header">
                        <h3>🔑 API Key Management</h3>
                    </div>
                    
                    <!-- Existing Keys Table (Desktop) -->
                    <div class="table-container desktop-only">
                        <table>
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Key</th>
                                    <th>RPM</th>
                                    <th>RPD</th>
                                    <th>Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {keys_html}
                            </tbody>
                        </table>
                    </div>
                    
                    <!-- Existing Keys Cards (Mobile) -->
                    <div class="mobile-only" style="display: none;">
                        {keys_mobile_html}
                    </div>
                    
                    <!-- Create New API Key Form -->
                    <div style="margin-top: 28px; padding-top: 24px; border-top: 1px solid var(--border);">
                        <h4 style="margin-bottom: 16px; font-size: 15px; font-weight: 600; color: var(--text);">➕ Create New API Key</h4>
                        <form action="/create-key" method="post" class="create-key-form">
                            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 16px;">
                                <div class="form-group" style="margin-bottom: 0;">
                                    <label class="form-label">Key Name</label>
                                    <input type="text" name="name" class="form-input" placeholder="My API Key" required>
                                </div>
                                <div class="form-group" style="margin-bottom: 0;">
                                    <label class="form-label">RPM (Requests/Min)</label>
                                    <input type="number" name="rpm" class="form-input" value="60" min="1" max="1000" required>
                                </div>
                                <div class="form-group" style="margin-bottom: 0;">
                                    <label class="form-label">RPD (Requests/Day)</label>
                                    <input type="number" name="rpd" class="form-input" value="10000" min="1" required>
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary" style="width: 100%;">
                                <span>🔑</span> Generate API Key
                            </button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Auth Tokens Section -->
            <div id="section-auth" class="section">
                <div class="grid-2">
                    <div class="card">
                        <div class="section-header">
                            <h3>🔄 Token Collection</h3>
                        </div>
                        <div style="text-align: center; padding: 20px;">
                            <div id="collection-badge" class="collection-badge idle">
                                <span class="badge-dot"></span>
                                <span id="badge-text">Idle</span>
                            </div>
                            
                            <div class="progress-container">
                                <div class="progress-header">
                                    <span>Progress</span>
                                    <span id="progress-text">0 / 0</span>
                                </div>
                                <div class="progress-bar-bg">
                                    <div id="progress-bar" class="progress-bar-fill" style="width: 0%;"></div>
                                </div>
                            </div>

                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; text-align: left;">
                                <div class="form-group" style="margin-bottom: 0;">
                                    <label class="form-label">Count</label>
                                    <input type="number" id="collect-count" class="form-input" value="{config.get('token_collect_count', 15)}">
                                </div>
                                <div class="form-group" style="margin-bottom: 0;">
                                    <label class="form-label">Delay (s)</label>
                                    <input type="number" id="collect-delay" class="form-input" value="{config.get('token_collect_delay', 5)}">
                                </div>
                            </div>

                            <div style="display: flex; gap: 12px; justify-content: center; margin-top: 24px;">
                                <button id="start-collection-btn" class="btn btn-primary" onclick="startCollection()">
                                    <span>▶</span> Start Collection
                                </button>
                                <button id="stop-collection-btn" class="btn btn-danger" style="display: none;" onclick="stopCollection()">
                                    <span>⏹</span> Stop
                                </button>
                            </div>
                            <div style="margin-top: 20px; font-size: 13px; color: var(--text-muted); padding: 12px; background: var(--bg-dark); border-radius: 10px;" id="collection-status">
                                ✨ Ready to start collection
                            </div>
                            
                            <!-- Refresh Cloudflare Section -->
                            <div style="margin-top: 24px; padding-top: 20px; border-top: 1px solid var(--border-color);">
                                <div style="text-align: center;">
                                    <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">
                                        🔄 Refresh Cloudflare session to update cookies & models
                                    </p>
                                    <button id="refresh-cf-btn" class="btn btn-secondary" onclick="refreshCloudflare()" style="width: 100%;">
                                        <span>☁️</span> Refresh Cloudflare
                                    </button>
                                    <div id="cf-refresh-status" style="margin-top: 12px; font-size: 12px; color: var(--text-muted); display: none;"></div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="section-header" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
                            <h3>📝 Auth Tokens ({len(config.get('auth_tokens', []))})</h3>
                            <div style="display: flex; gap: 8px;">
                                <button class="btn btn-secondary" style="padding: 8px 12px; font-size: 13px;" onclick="document.getElementById('add-token-modal').style.display='flex'">
                                    <span>➕</span> Add Token
                                </button>
                                <form action="/delete-all-tokens" method="post" style="margin: 0;" onsubmit="return confirm('Are you sure you want to delete ALL tokens? This cannot be undone.');">
                                    <button type="submit" class="btn btn-danger" style="padding: 8px 12px; font-size: 13px;">
                                        <span>🗑️</span> Delete All
                                    </button>
                                </form>
                            </div>
                        </div>
                        <div class="token-list" style="max-height: 340px; overflow-y: auto; padding-right: 8px;">
                            {tokens_html}
                        </div>
                    </div>
                </div>
                
                <!-- Add Token Modal -->
                <div id="add-token-modal" class="modal-overlay" style="display: none;">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h3>➕ Add Auth Tokens</h3>
                            <button class="modal-close" onclick="document.getElementById('add-token-modal').style.display='none'">&times;</button>
                        </div>
                        <form action="/update-auth-tokens" method="post">
                            <div class="form-group">
                                <label class="form-label">Paste tokens below (one per line)</label>
                                <textarea name="auth_tokens" class="form-input" style="height: 200px;" placeholder="Paste new tokens here...
They will be added to existing tokens.">{auth_tokens_str}</textarea>
                            </div>
                            <div style="display: flex; gap: 12px; justify-content: flex-end;">
                                <button type="button" class="btn btn-secondary" onclick="document.getElementById('add-token-modal').style.display='none'">Cancel</button>
                                <button type="submit" class="btn btn-primary">
                                    <span>💾</span> Save Tokens
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Logs Section -->
            <div id="section-logs" class="section">
                <div class="card" style="height: calc(100vh - 160px); display: flex; flex-direction: column;">
                    <div class="section-header" style="margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
                        <h3>📜 Live System Logs</h3>
                        <div style="display: flex; gap: 8px;">
                            <button class="btn btn-secondary" style="padding: 10px 14px;" onclick="toggleAutoScroll()" data-tooltip="Toggle Auto-scroll">
                                <span id="autoscroll-icon">⏬</span>
                            </button>
                            <button class="btn btn-secondary" style="padding: 10px 14px;" onclick="clearLogs()" data-tooltip="Clear Logs">
                                🗑️
                            </button>
                        </div>
                    </div>
                    <div id="log-container" class="logs-container" style="flex: 1; overflow-y: auto;">
                        <div id="log-content">
                            <div class="log-entry" style="color: var(--text-muted);">
                                <span class="loading-dots"><span></span><span></span><span></span></span> Loading logs...
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Settings Section -->
            <div id="section-settings" class="section">
                <div class="grid-2">
                    <div class="card">
                        <div class="section-header">
                            <h3>🎯 Generation Parameters</h3>
                        </div>
                        <div style="background: rgba(255, 193, 7, 0.1); border: 1px solid rgba(255, 193, 7, 0.3); border-radius: 8px; padding: 10px 14px; margin-bottom: 16px;">
                            <p style="margin: 0; font-size: 12px; color: #ffc107;">
                                <strong>⚠️ Warning:</strong> From testing, these parameters may not work reliably due to LMArena's backend configurations. Use at your own risk.
                            </p>
                        </div>
                        <form action="/update-generation-settings" method="post">
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                                <div class="form-group">
                                    <label class="form-label">Temperature</label>
                                    <input type="number" class="form-input" name="default_temperature" value="{default_temp}" step="0.1" min="0" max="2">
                                    <small style="color: var(--text-muted); font-size: 11px;">Controls randomness (0-2)</small>
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Top P (Nucleus)</label>
                                    <input type="number" class="form-input" name="default_top_p" value="{default_top_p}" step="0.05" min="0" max="1">
                                    <small style="color: var(--text-muted); font-size: 11px;">Nucleus sampling (0-1)</small>
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Max Output Tokens</label>
                                    <input type="number" class="form-input" name="default_max_tokens" value="{default_max_tokens}" min="1" max="128000">
                                    <small style="color: var(--text-muted); font-size: 11px;">Maximum response length</small>
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Presence Penalty</label>
                                    <input type="number" class="form-input" name="default_presence_penalty" value="{default_pres_pen}" step="0.1" min="-2" max="2">
                                    <small style="color: var(--text-muted); font-size: 11px;">Penalize repeated topics (-2 to 2)</small>
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Frequency Penalty</label>
                                    <input type="number" class="form-input" name="default_frequency_penalty" value="{default_freq_pen}" step="0.1" min="-2" max="2">
                                    <small style="color: var(--text-muted); font-size: 11px;">Penalize repeated words (-2 to 2)</small>
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary" style="margin-top: 8px;">
                                <span>💾</span> Save Generation Settings
                            </button>
                        </form>
                    </div>

                    <div class="card">
                        <div class="section-header">
                            <h3>⚙️ Advanced Configuration</h3>
                        </div>
                        <form action="/update-collection-settings" method="post">
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                                <div class="form-group">
                                    <label class="form-label">Chunk Size (chars)</label>
                                    <input type="number" class="form-input" name="chunk_size" value="{chunk_size}" min="1000" step="1000">
                                    <small style="color: var(--text-muted); font-size: 11px;">Max prompt chunk size</small>
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Rotation Limit</label>
                                    <input type="number" class="form-input" name="chunk_rotation_limit" value="{chunk_rotation_limit}" min="1" max="20">
                                    <small style="color: var(--text-muted); font-size: 11px;">Chunks before session rotation</small>
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary" style="margin-top: 8px;">
                                <span>💾</span> Save Advanced Settings
                            </button>
                        </form>
                    </div>
                </div>

                <div class="grid-2" style="margin-top: 24px;">
                    <div class="card">
                        <div class="section-header">
                            <h3>💻 System Info</h3>
                        </div>
                        <div class="system-info">
                            <div class="system-info-row">
                                <span class="system-info-label">Debug Mode</span>
                                <span class="system-info-value" style="color: {'var(--success)' if DEBUG else 'var(--text-muted)'};">{'Enabled' if DEBUG else 'Disabled'}</span>
                            </div>
                            <div class="system-info-row">
                                <span class="system-info-label">Port</span>
                                <span class="system-info-value">{PORT}</span>
                            </div>
                            <div class="system-info-row">
                                <span class="system-info-label">Chunk Size</span>
                                <span class="system-info-value">{chunk_size:,}</span>
                            </div>
                            <div class="system-info-row">
                                <span class="system-info-label">Rotation Limit</span>
                                <span class="system-info-value">{chunk_rotation_limit}</span>
                            </div>
                            <div class="system-info-row">
                                <span class="system-info-label">Sticky Sessions</span>
                                <span class="system-info-value" style="color: {'var(--success)' if STICKY_SESSIONS else 'var(--text-muted)'};">{'Enabled' if STICKY_SESSIONS else 'Disabled'}</span>
                            </div>
                        </div>
                    </div>

                    <div class="card">
                        <div style="text-align: center; padding: 24px; background: linear-gradient(135deg, var(--bg-dark) 0%, rgba(59, 130, 246, 0.05) 100%); border-radius: 16px; border: 1px solid var(--border);">
                            <div style="font-size: 56px; margin-bottom: 16px; filter: drop-shadow(0 0 20px var(--primary-glow)); animation: pulse-glow 3s infinite;">🚀</div>
                            <h2 style="margin-bottom: 8px; font-size: 24px; background: linear-gradient(135deg, var(--text-main), var(--primary-light)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">LMArena Bridge</h2>
                            <p style="color: var(--text-muted); font-size: 14px;">High-performance API proxy</p>
                            <div style="margin-top: 16px; font-size: 12px; color: var(--text-muted);">
                                Made with ❤️ by <span style="color: var(--primary-light);">@rumoto</span> & <span style="color: var(--primary-light);">@norenaboi</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Profile Section -->
            <div id="section-profile" class="section">
                <div class="grid-2">
                    <div class="card">
                        <div class="section-header">
                            <h3>👤 Profile Settings</h3>
                        </div>
                        <form action="/update-profile" method="post">
                            <div style="text-align: center; margin-bottom: 32px;">
                                <div class="profile-avatar-large" style="width: 100px; height: 100px; background: linear-gradient(135deg, var(--primary), var(--primary-dark)); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 48px; margin: 0 auto 16px; box-shadow: 0 8px 32px var(--primary-glow); border: 3px solid var(--border);">
                                    {config.get('profile_avatar', '👤')}
                                </div>
                                <div style="font-size: 20px; font-weight: 600; color: var(--text-main);">{config.get('profile_name', 'Admin User')}</div>
                                <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Dashboard Administrator</div>
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Display Name</label>
                                <input type="text" class="form-input" name="profile_name" value="{config.get('profile_name', 'Admin User')}" placeholder="Enter your name" maxlength="30">
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Profile Avatar</label>
                                <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">Choose an emoji or type a single character</p>
                                <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px;">
                                    <button type="button" class="avatar-option" onclick="document.querySelector('[name=profile_avatar]').value='👤'">👤</button>
                                    <button type="button" class="avatar-option" onclick="document.querySelector('[name=profile_avatar]').value='😎'">😎</button>
                                    <button type="button" class="avatar-option" onclick="document.querySelector('[name=profile_avatar]').value='🧑‍💻'">🧑‍💻</button>
                                    <button type="button" class="avatar-option" onclick="document.querySelector('[name=profile_avatar]').value='🚀'">🚀</button>
                                    <button type="button" class="avatar-option" onclick="document.querySelector('[name=profile_avatar]').value='⭐'">⭐</button>
                                    <button type="button" class="avatar-option" onclick="document.querySelector('[name=profile_avatar]').value='🔥'">🔥</button>
                                    <button type="button" class="avatar-option" onclick="document.querySelector('[name=profile_avatar]').value='💎'">💎</button>
                                    <button type="button" class="avatar-option" onclick="document.querySelector('[name=profile_avatar]').value='🎯'">🎯</button>
                                    <button type="button" class="avatar-option" onclick="document.querySelector('[name=profile_avatar]').value='🌟'">🌟</button>
                                    <button type="button" class="avatar-option" onclick="document.querySelector('[name=profile_avatar]').value='👑'">👑</button>
                                    <button type="button" class="avatar-option" onclick="document.querySelector('[name=profile_avatar]').value='🦊'">🦊</button>
                                    <button type="button" class="avatar-option" onclick="document.querySelector('[name=profile_avatar]').value='🐱'">🐱</button>
                                </div>
                                <input type="text" class="form-input" name="profile_avatar" value="{config.get('profile_avatar', '👤')}" placeholder="Or type a character" maxlength="2" style="text-align: center; font-size: 24px;">
                            </div>
                            
                            <button type="submit" class="btn btn-primary" style="width: 100%;">
                                <span>💾</span> Save Profile
                            </button>
                        </form>
                    </div>

                    <div class="card">
                        <div class="section-header">
                            <h3>📊 Your Activity</h3>
                        </div>
                        <div class="system-info">
                            <div class="system-info-row">
                                <span class="system-info-label">Total Requests Made</span>
                                <span class="system-info-value">{total_requests:,}</span>
                            </div>
                            <div class="system-info-row">
                                <span class="system-info-label">Active API Keys</span>
                                <span class="system-info-value">{len(api_keys)}</span>
                            </div>
                            <div class="system-info-row">
                                <span class="system-info-label">Auth Tokens</span>
                                <span class="system-info-value">{len(auth_tokens)}</span>
                            </div>
                            <div class="system-info-row">
                                <span class="system-info-label">Session Uptime</span>
                                <span class="system-info-value">{uptime_str}</span>
                            </div>
                        </div>
                        
                        <div style="margin-top: 32px; padding: 20px; background: linear-gradient(135deg, var(--bg-dark) 0%, rgba(16, 185, 129, 0.05) 100%); border-radius: 16px; border: 1px solid var(--border);">
                            <div style="display: flex; align-items: center; gap: 16px;">
                                <div style="width: 48px; height: 48px; background: linear-gradient(135deg, var(--success), #059669); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px;">
                                    ✓
                                </div>
                                <div>
                                    <div style="font-weight: 600; color: var(--text-main); margin-bottom: 4px;">Account Active</div>
                                    <div style="font-size: 13px; color: var(--text-muted);">All systems operational</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <script>
        // Generate background particles
        function createParticles() {{
            const container = document.getElementById('particles');
            const particleCount = 30;
            for (let i = 0; i < particleCount; i++) {{
                const particle = document.createElement('div');
                particle.className = 'particle';
                particle.style.left = Math.random() * 100 + '%';
                particle.style.animationDelay = Math.random() * 15 + 's';
                particle.style.animationDuration = (10 + Math.random() * 10) + 's';
                container.appendChild(particle);
            }}
        }}
        createParticles();

        // Sidebar Toggle
        function toggleSidebar() {{
            const sidebar = document.getElementById('sidebar');
            const overlay = document.getElementById('sidebarOverlay');
            sidebar.classList.toggle('open');
            overlay.classList.toggle('active');
        }}

        function closeSidebar() {{
            const sidebar = document.getElementById('sidebar');
            const overlay = document.getElementById('sidebarOverlay');
            sidebar.classList.remove('open');
            overlay.classList.remove('active');
        }}

        // Ripple Effect for buttons
        document.querySelectorAll('.btn').forEach(btn => {{
            btn.addEventListener('click', function(e) {{
                const rect = this.getBoundingClientRect();
                const ripple = document.createElement('span');
                ripple.className = 'ripple';
                ripple.style.left = (e.clientX - rect.left) + 'px';
                ripple.style.top = (e.clientY - rect.top) + 'px';
                this.appendChild(ripple);
                setTimeout(() => ripple.remove(), 600);
            }});
        }});

        // Section Navigation with animation
        function showSection(name) {{
            // Update UI
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.getElementById('section-' + name).classList.add('active');
            
            document.querySelectorAll('.nav-item').forEach(l => l.classList.remove('active'));
            event.currentTarget.classList.add('active');
            
            // Update Title with animation
            const titleEl = document.getElementById('page-title');
            titleEl.style.opacity = '0';
            titleEl.style.transform = 'translateY(-10px)';
            
            const titles = {{
                'dashboard': '📊 Dashboard',
                'models': '🤖 Models',
                'leaderboard': '🏆 Leaderboard',
                'keys': '🔑 API Keys',
                'auth': '🛡️ Auth Tokens',
                'logs': '📜 Live Logs',
                'settings': '⚙️ Settings',
                'profile': '👤 Profile'
            }};
            
            setTimeout(() => {{
                titleEl.textContent = titles[name];
                titleEl.style.opacity = '1';
                titleEl.style.transform = 'translateY(0)';
            }}, 150);

            // Handle Polling
            if (name === 'logs') startLogsPolling();
            else stopLogsPolling();
            
            if (name === 'auth') updateCollectionStatus();
            
            // Close sidebar on mobile
            if (window.innerWidth <= 768) {{
                closeSidebar();
            }}
        }}

        // Add transition to page title
        document.getElementById('page-title').style.transition = 'all 0.3s ease';

        // Charts with enhanced styling
        const statsData = {json.dumps(top_models)};
        const modelNames = Object.keys(statsData).slice(0, 10);
        const modelCounts = Object.values(statsData).slice(0, 10);
        
        const colors = [
            '#3b82f6', '#6366f1', '#8b5cf6', '#a855f7', '#d946ef',
            '#ec4899', '#f43f5e', '#f97316', '#eab308', '#10b981'
        ];

        const gradientColors = colors.map(color => {{
            return color;
        }});
        
        if (modelNames.length > 0) {{
            Chart.defaults.color = '#94a3b8';
            Chart.defaults.borderColor = '#1e3a5f';
            Chart.defaults.font.family = "'Inter', sans-serif";
            
            const pieChart = new Chart(document.getElementById('modelPieChart'), {{
                type: 'doughnut',
                data: {{
                    labels: modelNames,
                    datasets: [{{
                        data: modelCounts,
                        backgroundColor: colors,
                        borderWidth: 2,
                        borderColor: '#0a1628',
                        hoverOffset: 8,
                        hoverBorderWidth: 3,
                        hoverBorderColor: '#ffffff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '65%',
                    plugins: {{
                        legend: {{ 
                            position: 'right', 
                            labels: {{ 
                                boxWidth: 12,
                                padding: 16,
                                usePointStyle: true,
                                pointStyle: 'circle'
                            }}
                        }}
                    }},
                    animation: {{
                        animateRotate: true,
                        animateScale: true,
                        duration: 1000,
                        easing: 'easeOutQuart'
                    }}
                }}
            }});
            
            // Bar chart removed - replaced with static LMArena top models list
        }}

        // Token Collection Logic with enhanced UI
        let collectionInterval = null;
        
        async function startCollection() {{
            const count = document.getElementById('collect-count').value;
            const delay = document.getElementById('collect-delay').value;
            const formData = new FormData();
            formData.append('count', count);
            formData.append('delay', delay);
            
            const startBtn = document.getElementById('start-collection-btn');
            startBtn.innerHTML = '<span class="loading-dots"><span></span><span></span><span></span></span> Starting...';
            startBtn.disabled = true;
            
            try {{
                const response = await fetch('/start-token-collection', {{ method: 'POST', body: formData }});
                const data = await response.json();
                if (data.error) {{ 
                    alert(data.error); 
                    startBtn.innerHTML = '<span>▶</span> Start Collection';
                    startBtn.disabled = false;
                    return; 
                }}
                
                startBtn.style.display = 'none';
                startBtn.innerHTML = '<span>▶</span> Start Collection';
                startBtn.disabled = false;
                document.getElementById('stop-collection-btn').style.display = 'inline-flex';
                collectionInterval = setInterval(updateCollectionStatus, 1000);
                updateCollectionStatus();
            }} catch (e) {{ 
                alert('Error starting collection');
                startBtn.innerHTML = '<span>▶</span> Start Collection';
                startBtn.disabled = false;
            }}
        }}

        async function stopCollection() {{
            try {{
                await fetch('/stop-token-collection', {{ method: 'POST' }});
                if (collectionInterval) {{ clearInterval(collectionInterval); collectionInterval = null; }}
                document.getElementById('start-collection-btn').style.display = 'inline-flex';
                document.getElementById('stop-collection-btn').style.display = 'none';
                updateCollectionStatus();
            }} catch (e) {{ console.error(e); }}
        }}

        async function refreshCloudflare() {{
            const btn = document.getElementById('refresh-cf-btn');
            const statusEl = document.getElementById('cf-refresh-status');
            
            btn.innerHTML = '<span class="loading-dots"><span></span><span></span><span></span></span> Refreshing...';
            btn.disabled = true;
            statusEl.style.display = 'block';
            statusEl.innerHTML = '⏳ Refreshing Cloudflare session...';
            statusEl.style.color = 'var(--text-muted)';
            
            try {{
                const response = await fetch('/refresh-tokens', {{ method: 'POST' }});
                if (response.redirected || response.ok) {{
                    statusEl.innerHTML = '✅ Cloudflare session refreshed! Reloading page...';
                    statusEl.style.color = 'var(--success)';
                    setTimeout(() => window.location.reload(), 1500);
                }} else {{
                    throw new Error('Refresh failed');
                }}
            }} catch (e) {{
                statusEl.innerHTML = '❌ Failed to refresh. Check console for details.';
                statusEl.style.color = 'var(--error)';
                btn.innerHTML = '<span>☁️</span> Refresh Cloudflare';
                btn.disabled = false;
                console.error('Cloudflare refresh error:', e);
            }}
        }}

        async function updateCollectionStatus() {{
            try {{
                const response = await fetch('/token-collection-status');
                const data = await response.json();
                
                const statusEl = document.getElementById('collection-status');
                statusEl.innerHTML = data.current_status;
                
                document.getElementById('progress-text').textContent = `${{data.collected}} / ${{data.target}}`;
                const percent = data.target > 0 ? (data.collected / data.target) * 100 : 0;
                document.getElementById('progress-bar').style.width = `${{percent}}%`;
                
                const badge = document.getElementById('collection-badge');
                const badgeText = document.getElementById('badge-text');
                
                badge.classList.remove('idle', 'running', 'done');
                
                if (data.running) {{
                    badge.classList.add('running');
                    badgeText.textContent = '⚡ Running';
                }} else {{
                    if (data.collected > 0) {{
                        badge.classList.add('done');
                        badgeText.textContent = '✅ Done';
                    }} else {{
                        badge.classList.add('idle');
                        badgeText.textContent = '💤 Idle';
                    }}
                    
                    if (collectionInterval && !data.running) {{
                        clearInterval(collectionInterval);
                        collectionInterval = null;
                        document.getElementById('start-collection-btn').style.display = 'inline-flex';
                        document.getElementById('stop-collection-btn').style.display = 'none';
                    }}
                }}
            }} catch (e) {{ console.error(e); }}
        }}

        // Logs Logic with enhanced styling
        let autoScroll = true;
        let logsInterval = null;
        
        function toggleAutoScroll() {{
            autoScroll = !autoScroll;
            const icon = document.getElementById('autoscroll-icon');
            icon.textContent = autoScroll ? '⏬' : '⏸️';
            icon.style.transform = 'scale(1.2)';
            setTimeout(() => icon.style.transform = 'scale(1)', 200);
        }}

        async function fetchLogs() {{
            try {{
                const response = await fetch('/api/logs?limit=200');
                const data = await response.json();
                if (data.logs) {{
                    const container = document.getElementById('log-content');
                    const levelClasses = {{ 
                        'INFO': 'log-level-info', 
                        'SUCCESS': 'log-level-success', 
                        'WARN': 'log-level-warn', 
                        'ERROR': 'log-level-error', 
                        'DEBUG': 'log-level-debug' 
                    }};
                    
                    container.innerHTML = data.logs.map(log => {{
                        const levelClass = levelClasses[log.level] || 'log-level-debug';
                        return `<div class="log-entry">
                            <span class="log-timestamp">${{log.timestamp}}</span> 
                            <span class="log-level ${{levelClass}}">${{log.level}}</span> 
                            <span class="log-message">${{log.message}}</span>
                        </div>`;
                    }}).join('');
                    
                    if (autoScroll) {{
                        const logContainer = document.getElementById('log-container');
                        logContainer.scrollTop = logContainer.scrollHeight;
                    }}
                }}
            }} catch (e) {{ console.error(e); }}
        }}

        async function clearLogs() {{
            await fetch('/api/clear-logs', {{ method: 'POST' }});
            document.getElementById('log-content').innerHTML = '<div class="log-entry" style="color: var(--text-muted);">🗑️ Logs cleared</div>';
        }}

        // Leaderboard functionality
        let leaderboardRefreshing = false;
        
        async function loadLeaderboard() {{
            // Just load cached data (quick)
            const loading = document.getElementById('leaderboard-loading');
            const error = document.getElementById('leaderboard-error');
            const tableContainer = document.getElementById('leaderboard-table-container');
            const updatedEl = document.getElementById('leaderboard-updated');
            
            loading.style.display = 'block';
            error.style.display = 'none';
            tableContainer.style.opacity = '0.5';
            
            try {{
                const response = await fetch('/api/leaderboard?category=overall');
                if (!response.ok) throw new Error('Failed to fetch');
                
                const data = await response.json();
                
                if (data.last_updated) {{
                    updatedEl.textContent = `Last updated: ${{data.last_updated}}`;
                }}
                
                renderLeaderboard(data);
                loading.style.display = 'none';
                tableContainer.style.opacity = '1';
            }} catch (e) {{
                console.error('Leaderboard error:', e);
                loading.style.display = 'none';
                error.style.display = 'block';
                tableContainer.style.opacity = '1';
            }}
        }}
        
        async function refreshLeaderboard() {{
            // Fetch fresh data using browser automation (slow but accurate)
            if (leaderboardRefreshing) return;
            leaderboardRefreshing = true;
            
            const loading = document.getElementById('leaderboard-loading');
            const error = document.getElementById('leaderboard-error');
            const tableContainer = document.getElementById('leaderboard-table-container');
            const updatedEl = document.getElementById('leaderboard-updated');
            const refreshBtn = document.querySelector('#section-leaderboard .btn-secondary');
            
            // Update UI for long operation
            loading.style.display = 'block';
            loading.innerHTML = '<div class="loading-dots"><span></span><span></span><span></span></div><p style="margin-top: 16px; color: var(--text-muted);">🌐 Fetching from LMArena using browser automation...<br><small>This may take 10-30 seconds (bypassing Cloudflare)</small></p>';
            error.style.display = 'none';
            tableContainer.style.opacity = '0.3';
            if (refreshBtn) {{
                refreshBtn.disabled = true;
                refreshBtn.innerHTML = '⏳ Fetching...';
            }}
            
            try {{
                const response = await fetch('/api/leaderboard/refresh', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }}
                }});
                
                const data = await response.json();
                
                if (data.last_updated) {{
                    updatedEl.textContent = `Last updated: ${{data.last_updated}}`;
                }}
                
                if (data.success) {{
                    updatedEl.innerHTML = `✅ ${{data.message}} • ${{data.last_updated}}`;
                }} else {{
                    updatedEl.innerHTML = `⚠️ ${{data.message}} • Showing cached: ${{data.last_updated}}`;
                }}
                
                renderLeaderboard(data);
                loading.style.display = 'none';
                tableContainer.style.opacity = '1';
            }} catch (e) {{
                console.error('Leaderboard refresh error:', e);
                loading.style.display = 'none';
                error.style.display = 'block';
                error.innerHTML = '<div style="font-size: 48px; margin-bottom: 16px;">⚠️</div><p>Failed to refresh leaderboard</p><p style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">' + e.message + '</p><button class="btn btn-primary" onclick="loadLeaderboard()" style="margin-top: 16px;">Show Cached Data</button>';
                tableContainer.style.opacity = '1';
            }} finally {{
                leaderboardRefreshing = false;
                if (refreshBtn) {{
                    refreshBtn.disabled = false;
                    refreshBtn.innerHTML = '🔄 Refresh';
                }}
                // Reset loading text
                loading.innerHTML = '<div class="loading-dots"><span></span><span></span><span></span></div><p style="margin-top: 16px; color: var(--text-muted);">Loading leaderboard data...</p>';
            }}
        }}
        
        function renderLeaderboard(data) {{
            const tbody = document.getElementById('leaderboard-body');
            
            if (!data.models || data.models.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 40px;">No data available. Click Refresh to fetch rankings.</td></tr>';
                return;
            }}
            
            // Provider color mapping
            const providerColors = {{
                'OpenAI': '#10a37f',
                'Anthropic': '#d4a27f',
                'Google': '#4285f4',
                'xAI': '#1da1f2',
                'Meta': '#0668e1',
                'Mistral': '#ff7000',
                'DeepSeek': '#5b6ee1',
                'Alibaba': '#ff6a00',
                'Cohere': '#39594d',
                'Microsoft': '#00a4ef',
                'Nvidia': '#76b900',
            }};
            
            let html = '';
            data.models.slice(0, 50).forEach((model, index) => {{
                const rank = model.rank || (index + 1);
                const rankBadge = rank <= 3 ? 
                    `<span style="background: ${{rank === 1 ? 'linear-gradient(135deg, #ffd700, #ffb700)' : rank === 2 ? 'linear-gradient(135deg, #c0c0c0, #a0a0a0)' : 'linear-gradient(135deg, #cd7f32, #a0522d)'}}; color: #000; padding: 4px 10px; border-radius: 8px; font-weight: 700;">${{rank}}</span>` :
                    `<span style="color: var(--text-muted);">${{rank}}</span>`;
                
                const provider = model.provider || 'Unknown';
                const providerColor = providerColors[provider] || 'var(--text-muted)';
                const elo = model.elo || '-';
                const ci = model.ci || '-';
                const votes = model.votes || '-';
                
                html += `
                    <tr style="animation: fadeIn 0.3s ease ${{index * 0.02}}s both;">
                        <td style="text-align: center;">${{rankBadge}}</td>
                        <td>
                            <span style="color: ${{providerColor}}; font-weight: 500; font-size: 13px;">${{provider}}</span>
                        </td>
                        <td>
                            <div style="font-weight: 600; color: var(--text-main);">${{model.name}}</div>
                        </td>
                        <td style="text-align: center;">
                            <span style="font-weight: 600; color: var(--primary-light);">${{elo}}</span>
                        </td>
                        <td style="text-align: center; font-size: 12px; color: var(--text-muted);">${{ci}}</td>
                        <td style="text-align: center; font-size: 12px; color: var(--text-secondary);">${{votes}}</td>
                    </tr>
                `;
            }});
            
            tbody.innerHTML = html;
        }}

        function startLogsPolling() {{
            if (!logsInterval) {{ fetchLogs(); logsInterval = setInterval(fetchLogs, 2000); }}
        }}

        function stopLogsPolling() {{
            if (logsInterval) {{ clearInterval(logsInterval); logsInterval = null; }}
        }}

        // Card entrance animation
        function animateCards() {{
            const cards = document.querySelectorAll('.card');
            cards.forEach((card, index) => {{
                card.style.opacity = '0';
                card.style.transform = 'translateY(20px)';
                setTimeout(() => {{
                    card.style.transition = 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)';
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }}, index * 100);
            }});
        }}

        // Uptime counter
        let uptimeSeconds = {int(time.time() - server_start_time)};
        function updateUptime() {{
            uptimeSeconds++;
            const days = Math.floor(uptimeSeconds / 86400);
            const hours = Math.floor((uptimeSeconds % 86400) / 3600);
            const minutes = Math.floor((uptimeSeconds % 3600) / 60);
            const seconds = uptimeSeconds % 60;
            
            let parts = [];
            if (days > 0) parts.push(days + 'd');
            if (hours > 0) parts.push(hours + 'h');
            if (minutes > 0) parts.push(minutes + 'm');
            parts.push(seconds + 's');
            
            const uptimeEl = document.getElementById('uptime-value');
            if (uptimeEl) uptimeEl.textContent = parts.join(' ');
        }}
        setInterval(updateUptime, 1000);

        // Keyboard navigation
        document.addEventListener('keydown', (e) => {{
            if (e.key === 'Escape' && window.innerWidth <= 768) {{
                closeSidebar();
            }}
        }});

        // Touch swipe for mobile sidebar - only for edge swipes, don't interfere with buttons
        let touchStartX = 0;
        let touchStartY = 0;
        let touchEndX = 0;
        let touchEndY = 0;
        let isSwiping = false;
        
        document.addEventListener('touchstart', (e) => {{
            touchStartX = e.changedTouches[0].screenX;
            touchStartY = e.changedTouches[0].screenY;
            isSwiping = false;
            
            // Only track swipes that start from the left edge (first 30px) or when sidebar is open
            const sidebar = document.getElementById('sidebar');
            if (touchStartX < 30 || sidebar.classList.contains('open')) {{
                isSwiping = true;
            }}
        }}, {{ passive: true }});
        
        document.addEventListener('touchmove', (e) => {{
            // If it's a horizontal swipe from edge, prevent scroll
            if (isSwiping) {{
                const currentX = e.changedTouches[0].screenX;
                const currentY = e.changedTouches[0].screenY;
                const diffX = Math.abs(currentX - touchStartX);
                const diffY = Math.abs(currentY - touchStartY);
                
                // If mostly horizontal movement, it's a swipe
                if (diffX > diffY && diffX > 10) {{
                    // Don't prevent default - let the swipe happen naturally
                }}
            }}
        }}, {{ passive: true }});
        
        document.addEventListener('touchend', (e) => {{
            if (!isSwiping) return;
            
            touchEndX = e.changedTouches[0].screenX;
            touchEndY = e.changedTouches[0].screenY;
            
            const diffX = touchEndX - touchStartX;
            const diffY = Math.abs(touchEndY - touchStartY);
            const swipeThreshold = 60;
            
            // Only handle if horizontal swipe is dominant
            if (Math.abs(diffX) > diffY && Math.abs(diffX) > swipeThreshold) {{
                if (diffX > 0 && touchStartX < 30) {{
                    // Swipe right from left edge - open sidebar
                    document.getElementById('sidebar').classList.add('open');
                    document.getElementById('sidebarOverlay').classList.add('active');
                }} else if (diffX < 0) {{
                    // Swipe left - close sidebar
                    closeSidebar();
                }}
            }}
            
            isSwiping = false;
        }}, {{ passive: true }});

        // Load top 7 models preview from leaderboard cache
        async function loadTopModelsPreview() {{
            const container = document.getElementById('top-models-list');
            if (!container) return;
            
            try {{
                const response = await fetch('/api/leaderboard?category=overall');
                if (!response.ok) throw new Error('Failed to fetch');
                const data = await response.json();
                
                if (!data.models || data.models.length === 0) {{
                    container.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 20px;">No leaderboard data. Click Refresh in Leaderboard tab.</div>';
                    return;
                }}
                
                const providerColors = {{
                    'OpenAI': '#10a37f',
                    'Anthropic': '#d4a27f',
                    'Google': '#4285f4',
                    'xAI': '#1da1f2',
                    'Meta': '#0668e1',
                    'Mistral': '#ff7000',
                    'DeepSeek': '#5b6ee1',
                    'Alibaba': '#ff6a00',
                }};
                
                let html = '';
                data.models.slice(0, 7).forEach((model, index) => {{
                    const rank = index + 1;
                    const provider = model.provider || 'Unknown';
                    const providerColor = providerColors[provider] || 'var(--text-muted)';
                    const elo = model.elo || '-';
                    
                    if (rank <= 3) {{
                        const colors = ['#ffd700', '#c0c0c0', '#cd7f32'];
                        const bgColors = ['rgba(255,215,0,0.15)', 'rgba(192,192,192,0.12)', 'rgba(205,127,50,0.12)'];
                        html += `
                            <div style="display: flex; align-items: center; gap: 12px; padding: 10px 14px; background: linear-gradient(90deg, ${{bgColors[rank-1]}}, transparent); border-radius: 10px; border-left: 3px solid ${{colors[rank-1]}};">
                                <span style="font-size: 18px; font-weight: 800; color: ${{colors[rank-1]}}; width: 24px;">${{rank}}</span>
                                <div style="flex: 1;"><div style="font-weight: 600; color: var(--text-main);">${{model.name}}</div><div style="font-size: 11px; color: ${{providerColor}};">${{provider}}</div></div>
                                <span class="badge" style="font-size: 11px;">${{elo}}</span>
                            </div>
                        `;
                    }} else {{
                        html += `
                            <div style="display: flex; align-items: center; gap: 12px; padding: 8px 14px; background: var(--bg-dark); border-radius: 10px;">
                                <span style="font-size: 14px; font-weight: 700; color: var(--text-muted); width: 24px;">${{rank}}</span>
                                <div style="flex: 1;"><div style="font-weight: 500; color: var(--text-secondary);">${{model.name}}</div><div style="font-size: 11px; color: ${{providerColor}};">${{provider}}</div></div>
                                <span style="font-size: 11px; color: var(--text-muted);">${{elo}}</span>
                            </div>
                        `;
                    }}
                }});
                
                container.innerHTML = html;
            }} catch (e) {{
                console.error('Error loading top models:', e);
                container.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 20px;">Failed to load. Click to view Leaderboard.</div>';
            }}
        }}

        // Init
        updateCollectionStatus();
        animateCards();
        loadTopModelsPreview();
        
        // Add smooth hover effect to table rows
        document.querySelectorAll('tbody tr').forEach(row => {{
            row.addEventListener('mouseenter', function() {{
                this.style.transform = 'scale(1.01)';
            }});
            row.addEventListener('mouseleave', function() {{
                this.style.transform = 'scale(1)';
            }});
        }});

        // Input focus effects
        document.querySelectorAll('.form-input').forEach(input => {{
            input.addEventListener('focus', function() {{
                this.parentElement.style.transform = 'scale(1.02)';
            }});
            input.addEventListener('blur', function() {{
                this.parentElement.style.transform = 'scale(1)';
            }});
        }});

        console.log('%c🚀 LMArena Bridge Dashboard', 'font-size: 20px; font-weight: bold; color: #3b82f6;');
        console.log('%cWelcome to the enhanced dashboard!', 'font-size: 12px; color: #94a3b8;');
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

# --- Leaderboard API ---
# Static leaderboard data - updated on server startup
import re

LEADERBOARD_FILE = "leaderboard_cache.json"

# Default hardcoded leaderboard data (fallback if fetch fails)
DEFAULT_LEADERBOARD = {
    "overall": [
        {"rank": 1, "name": "gemini-3-pro", "provider": "Google", "elo": 1400, "ci": "±5", "votes": "50K"},
        {"rank": 2, "name": "grok-4.1-thinking", "provider": "xAI", "elo": 1395, "ci": "±5", "votes": "45K"},
        {"rank": 3, "name": "claude-opus-4-5-thinking", "provider": "Anthropic", "elo": 1390, "ci": "±5", "votes": "40K"},
        {"rank": 4, "name": "grok-4.1", "provider": "xAI", "elo": 1385, "ci": "±5", "votes": "38K"},
        {"rank": 5, "name": "claude-opus-4-5", "provider": "Anthropic", "elo": 1380, "ci": "±5", "votes": "35K"},
        {"rank": 6, "name": "gpt-5.1-high", "provider": "OpenAI", "elo": 1375, "ci": "±5", "votes": "32K"},
        {"rank": 7, "name": "gemini-2.5-pro", "provider": "Google", "elo": 1370, "ci": "±5", "votes": "30K"},
        {"rank": 8, "name": "claude-sonnet-4-5-thinking", "provider": "Anthropic", "elo": 1365, "ci": "±5", "votes": "28K"},
        {"rank": 9, "name": "claude-opus-4-1-thinking", "provider": "Anthropic", "elo": 1360, "ci": "±5", "votes": "25K"},
        {"rank": 10, "name": "claude-sonnet-4-5", "provider": "Anthropic", "elo": 1355, "ci": "±5", "votes": "22K"},
        {"rank": 11, "name": "gpt-4.5-preview", "provider": "OpenAI", "elo": 1350, "ci": "±5", "votes": "20K"},
        {"rank": 12, "name": "claude-opus-4-1", "provider": "Anthropic", "elo": 1345, "ci": "±5", "votes": "18K"},
        {"rank": 13, "name": "chatgpt-4o-latest", "provider": "OpenAI", "elo": 1340, "ci": "±5", "votes": "16K"},
        {"rank": 14, "name": "gpt-5-high", "provider": "OpenAI", "elo": 1335, "ci": "±5", "votes": "15K"},
        {"rank": 15, "name": "gpt-5.1", "provider": "OpenAI", "elo": 1330, "ci": "±5", "votes": "14K"},
        {"rank": 16, "name": "o3", "provider": "OpenAI", "elo": 1325, "ci": "±5", "votes": "13K"},
        {"rank": 17, "name": "qwen3-max", "provider": "Alibaba", "elo": 1320, "ci": "±5", "votes": "12K"},
        {"rank": 18, "name": "grok-4-fast", "provider": "xAI", "elo": 1315, "ci": "±5", "votes": "11K"},
        {"rank": 19, "name": "kimi-k2-thinking", "provider": "Moonshot", "elo": 1310, "ci": "±5", "votes": "10K"},
        {"rank": 20, "name": "glm-4.6", "provider": "Zhipu", "elo": 1305, "ci": "±5", "votes": "9K"},
        {"rank": 21, "name": "deepseek-r1", "provider": "DeepSeek", "elo": 1300, "ci": "±5", "votes": "8K"},
        {"rank": 22, "name": "claude-3.5-sonnet", "provider": "Anthropic", "elo": 1295, "ci": "±5", "votes": "7K"},
        {"rank": 23, "name": "gemini-2.0-ultra", "provider": "Google", "elo": 1290, "ci": "±5", "votes": "6K"},
        {"rank": 24, "name": "gpt-4-turbo", "provider": "OpenAI", "elo": 1285, "ci": "±5", "votes": "5K"},
        {"rank": 25, "name": "llama-4-405b", "provider": "Meta", "elo": 1280, "ci": "±5", "votes": "5K"},
        {"rank": 26, "name": "mistral-large-2", "provider": "Mistral", "elo": 1275, "ci": "±5", "votes": "4K"},
        {"rank": 27, "name": "qwen-2.5-72b", "provider": "Alibaba", "elo": 1270, "ci": "±5", "votes": "4K"},
        {"rank": 28, "name": "command-r-plus", "provider": "Cohere", "elo": 1265, "ci": "±5", "votes": "3K"},
        {"rank": 29, "name": "yi-large", "provider": "01.AI", "elo": 1260, "ci": "±5", "votes": "3K"},
        {"rank": 30, "name": "claude-3-opus", "provider": "Anthropic", "elo": 1255, "ci": "±5", "votes": "3K"},
        {"rank": 31, "name": "gemini-1.5-pro", "provider": "Google", "elo": 1250, "ci": "±5", "votes": "2K"},
        {"rank": 32, "name": "gpt-4o", "provider": "OpenAI", "elo": 1245, "ci": "±5", "votes": "2K"},
        {"rank": 33, "name": "llama-3.1-405b", "provider": "Meta", "elo": 1240, "ci": "±5", "votes": "2K"},
        {"rank": 34, "name": "deepseek-v3", "provider": "DeepSeek", "elo": 1235, "ci": "±5", "votes": "2K"},
        {"rank": 35, "name": "nemotron-4-340b", "provider": "Nvidia", "elo": 1230, "ci": "±5", "votes": "1K"},
        {"rank": 36, "name": "phi-4", "provider": "Microsoft", "elo": 1225, "ci": "±5", "votes": "1K"},
        {"rank": 37, "name": "wizardlm-2-8x22b", "provider": "Microsoft", "elo": 1220, "ci": "±5", "votes": "1K"},
        {"rank": 38, "name": "reka-core", "provider": "Reka", "elo": 1215, "ci": "±5", "votes": "1K"},
        {"rank": 39, "name": "dbrx-instruct", "provider": "Databricks", "elo": 1210, "ci": "±5", "votes": "1K"},
        {"rank": 40, "name": "mixtral-8x22b", "provider": "Mistral", "elo": 1205, "ci": "±5", "votes": "1K"},
        {"rank": 41, "name": "claude-3-sonnet", "provider": "Anthropic", "elo": 1200, "ci": "±5", "votes": "1K"},
        {"rank": 42, "name": "gemma-2-27b", "provider": "Google", "elo": 1195, "ci": "±5", "votes": "1K"},
        {"rank": 43, "name": "llama-3-70b", "provider": "Meta", "elo": 1190, "ci": "±5", "votes": "1K"},
        {"rank": 44, "name": "qwen-72b", "provider": "Alibaba", "elo": 1185, "ci": "±5", "votes": "1K"},
        {"rank": 45, "name": "yi-34b", "provider": "01.AI", "elo": 1180, "ci": "±5", "votes": "1K"},
        {"rank": 46, "name": "starling-lm-7b", "provider": "Berkeley", "elo": 1175, "ci": "±5", "votes": "1K"},
        {"rank": 47, "name": "openchat-3.5", "provider": "OpenChat", "elo": 1170, "ci": "±5", "votes": "1K"},
        {"rank": 48, "name": "zephyr-7b", "provider": "HuggingFace", "elo": 1165, "ci": "±5", "votes": "1K"},
        {"rank": 49, "name": "vicuna-33b", "provider": "LMSYS", "elo": 1160, "ci": "±5", "votes": "1K"},
        {"rank": 50, "name": "llama-2-70b", "provider": "Meta", "elo": 1155, "ci": "±5", "votes": "1K"},
    ]
}

# In-memory leaderboard cache
leaderboard_data = {}

def load_leaderboard_cache():
    """Load leaderboard data from cache file or use defaults"""
    global leaderboard_data
    try:
        with open(LEADERBOARD_FILE, "r") as f:
            leaderboard_data = json.load(f)
            sync_log(f"📊 Loaded leaderboard cache ({len(leaderboard_data.get('overall', []))} models)", "INFO")
    except (FileNotFoundError, json.JSONDecodeError):
        leaderboard_data = DEFAULT_LEADERBOARD.copy()
        sync_log("📊 Using default leaderboard data", "INFO")

def save_leaderboard_cache():
    """Save leaderboard data to cache file"""
    try:
        with open(LEADERBOARD_FILE, "w") as f:
            json.dump(leaderboard_data, f, indent=2)
    except Exception as e:
        sync_log(f"⚠️ Failed to save leaderboard cache: {e}", "WARN")

async def fetch_leaderboard_with_browser():
    """Fetch leaderboard data using the global Camoufox browser (handles JS rendering)"""
    global leaderboard_data, global_page, global_browser
    
    await add_log("📊 Fetching leaderboard using browser (JS rendering)...", "INFO")
    
    if not global_browser:
        await add_log("⚠️ Browser not initialized, using cached leaderboard data", "WARN")
        return False
    
    leaderboard_page = None
    try:
        # Create a new page in the existing browser context
        context = global_browser.contexts[0] if global_browser.contexts else await global_browser.new_context()
        leaderboard_page = await context.new_page()
        
        await add_log("🌐 Navigating to LMArena leaderboard...", "DEBUG")
        await leaderboard_page.goto("https://lmarena.ai/leaderboard/text/overall", wait_until="networkidle", timeout=30000)
        
        # Wait for the table to render
        await asyncio.sleep(3)
        
        # Check for Cloudflare challenge
        title = await leaderboard_page.title()
        if "Just a moment" in title or "Cloudflare" in title:
            await add_log("🛡️ Cloudflare challenge on leaderboard, attempting to pass...", "WARN")
            passed = await handle_cloudflare_challenge(leaderboard_page, "leaderboard", max_wait=20)
            if not passed:
                await add_log("❌ Failed to pass Cloudflare on leaderboard", "ERROR")
                return False
            await asyncio.sleep(2)
        
        # Extract leaderboard data using JavaScript
        await add_log("📋 Extracting leaderboard data from page...", "DEBUG")
        models = await leaderboard_page.evaluate(r"""
            () => {
                const models = [];
                
                // Find all table rows
                const rows = document.querySelectorAll('table tbody tr');
                
                rows.forEach((row, index) => {
                    const cells = row.querySelectorAll('td');
                    if (cells.length >= 4) {
                        try {
                            // Extract all cell text content (cleaned)
                            const cellTexts = Array.from(cells).map(c => c.textContent.trim());
                            
                            let rank = index + 1;
                            let provider = '';
                            let name = '';
                            let elo = '';
                            let ci = '';
                            let votes = '';
                            
                            // First cell is usually rank
                            const firstCell = cellTexts[0];
                            if (/^\d+$/.test(firstCell)) {
                                rank = parseInt(firstCell);
                            }
                            
                            // Process each cell to identify its type
                            for (let i = 0; i < cellTexts.length; i++) {
                                const text = cellTexts[i];
                                if (!text) continue;
                                
                                // Skip rank cell
                                if (i === 0 && /^\d+$/.test(text)) continue;
                                
                                // ELO: 4-digit number starting with 1 (like 1491, 1400, etc)
                                if (!elo && /^1[3-5]\d{2}$/.test(text)) {
                                    elo = text;
                                    continue;
                                }
                                
                                // CI: small number, often just a single or double digit
                                if (!ci && /^\d{1,2}$/.test(text) && parseInt(text) < 100) {
                                    ci = '±' + text;
                                    continue;
                                }
                                
                                // Votes: comma-separated number (like 12,087) or number with K/M
                                if (!votes && (/^\d{1,3}(,\d{3})+$/.test(text) || /^\d+(\.\d+)?[KkMm]$/.test(text) || /^\d{4,}$/.test(text))) {
                                    votes = text;
                                    continue;
                                }
                            }
                            
                            // Find model name - look for the cell with dashes that looks like a model name
                            // Usually it's one of the first few cells after rank
                            for (let i = 1; i < Math.min(cellTexts.length, 5); i++) {
                                const text = cellTexts[i];
                                if (text && text.length > 5 && text.includes('-') && 
                                    !text.includes('±') && 
                                    !/^\d/.test(text) &&
                                    !/^[\d\.\,\+\-KkMm\s]+$/.test(text)) {
                                    name = text;
                                    break;
                                }
                            }
                            
                            // If no name found with dash, try any longer text
                            if (!name) {
                                for (let i = 1; i < cellTexts.length; i++) {
                                    const text = cellTexts[i];
                                    if (text && text.length > 10 && 
                                        !/^\d/.test(text) &&
                                        !text.includes('±')) {
                                        name = text;
                                        break;
                                    }
                                }
                            }
                            
                            // Find provider from known list
                            const knownProviders = ['OpenAI', 'Anthropic', 'Google', 'Meta', 'xAI', 'Mistral', 
                                'DeepSeek', 'Alibaba', 'Cohere', 'Microsoft', 'Nvidia', 'Zhipu', 'Moonshot',
                                '01.AI', 'HuggingFace', 'Databricks', 'Reka', 'Berkeley', 'LMSYS', 'Tencent',
                                'Baidu', 'Together', 'Perplexity', 'AI21', 'Amazon', 'Apple'];
                            
                            // Check cells for exact provider match
                            for (let i = 0; i < cellTexts.length; i++) {
                                const text = cellTexts[i];
                                for (const p of knownProviders) {
                                    if (text === p || text.toLowerCase() === p.toLowerCase()) {
                                        provider = p;
                                        break;
                                    }
                                }
                                if (provider) break;
                            }
                            
                            // Also check image alt text for provider
                            if (!provider) {
                                const imgs = row.querySelectorAll('img');
                                for (const img of imgs) {
                                    const alt = (img.alt || img.title || '').toLowerCase();
                                    for (const p of knownProviders) {
                                        if (alt.includes(p.toLowerCase())) {
                                            provider = p;
                                            break;
                                        }
                                    }
                                    if (provider) break;
                                }
                            }
                            
                            // Fallback: extract provider from model name if it starts with known prefix
                            if (!provider && name) {
                                for (const p of knownProviders) {
                                    if (name.toLowerCase().startsWith(p.toLowerCase())) {
                                        provider = p;
                                        break;
                                    }
                                }
                            }
                            
                            if (name && rank <= 50) {
                                models.push({ 
                                    rank, 
                                    name, 
                                    provider: provider || 'Unknown',
                                    elo: elo || '',
                                    ci: ci || '',
                                    votes: votes || ''
                                });
                            }
                        } catch (e) {
                            // Skip this row on error
                        }
                    }
                });
                
                return models;
            }
        """)
        
        if models and len(models) > 0:
            # Clean up model names (remove org prefixes if present in name)
            # Include both with and without spaces, and common variations
            prefix_patterns = [
                'Anthropic', 'anthropic',
                'OpenAI', 'openai', 
                'Google', 'google',
                'Meta', 'meta',
                'xAI', 'xai', 'XAI',
                'Mistral', 'mistral',
                'DeepSeek', 'deepseek', 'Deepseek',
                'Alibaba', 'alibaba',
                'Cohere', 'cohere',
                'Microsoft', 'microsoft',
                'Nvidia', 'nvidia', 'NVIDIA',
                'Zhipu', 'zhipu',
                'Moonshot', 'moonshot', 'MoonshotAI', 'moonshotai',
                '01.AI', '01.ai',
                'HuggingFace', 'huggingface', 'Huggingface',
                'Databricks', 'databricks',
                'Reka', 'reka',
                'Berkeley', 'berkeley',
                'LMSYS', 'lmsys',
                'Tencent', 'tencent',
                'Baidu', 'baidu',
                'Together', 'together',
                'Perplexity', 'perplexity',
                'AI21', 'ai21',
                'Amazon', 'amazon', 'AWS', 'aws',
                'Apple', 'apple',
                'Qwen Icon', 'Qwen', 'qwen',
                'Azure', 'azure',
                'Minimax', 'minimax',
                'Stepfun', 'stepfun',
                'InternLM', 'internlm',
                'OpenChat', 'openchat',
                'Snowflake', 'snowflake',
                'AntGroup', 'antgroup',
                'RWKV', 'rwkv',
                'Stability', 'stability',
            ]
            
            cleaned = []
            for m in models:
                name = m.get('name', '')
                original_name = name
                
                # Try to remove prefix (with or without space after it)
                for prefix in prefix_patterns:
                    # Check with space
                    if name.startswith(prefix + ' '):
                        name = name[len(prefix) + 1:]
                        break
                    # Check without space (concatenated)
                    elif name.startswith(prefix) and len(name) > len(prefix):
                        # Make sure we're not cutting a legitimate model name
                        remainder = name[len(prefix):]
                        # If remainder starts with lowercase or dash, it's likely concatenated
                        if remainder and (remainder[0].islower() or remainder[0] in '-_'):
                            name = remainder
                            break
                
                # Also strip any leading/trailing whitespace
                name = name.strip()
                
                # If name became empty, use original
                if not name:
                    name = original_name
                
                cleaned.append({
                    "rank": m["rank"], 
                    "name": name,
                    "provider": m.get("provider", "Unknown"),
                    "elo": m.get("elo", ""),
                    "ci": m.get("ci", ""),
                    "votes": m.get("votes", "")
                })
            
            # Deduplicate and sort
            seen = set()
            unique = []
            for m in sorted(cleaned, key=lambda x: x["rank"]):
                if m["rank"] not in seen and m["name"]:
                    seen.add(m["rank"])
                    unique.append(m)
            
            if unique:
                leaderboard_data["overall"] = unique[:50]
                leaderboard_data["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
                save_leaderboard_cache()
                await add_log(f"✅ Leaderboard updated with {len(unique)} models from browser", "SUCCESS")
                return True
        
        await add_log("⚠️ No models extracted from leaderboard page, keeping cached data", "WARN")
        return False
        
    except Exception as e:
        await add_log(f"⚠️ Leaderboard browser fetch failed: {e}", "WARN")
        return False
    finally:
        if leaderboard_page:
            try:
                await leaderboard_page.close()
            except:
                pass

async def update_leaderboard_on_startup():
    """Fetch fresh leaderboard data from LMArena on server startup"""
    # Wait a bit for browser to be ready
    await asyncio.sleep(5)
    await fetch_leaderboard_with_browser()

@app.get("/api/leaderboard")
async def get_leaderboard(request: Request, category: str = "overall"):
    """Return static leaderboard data"""
    session = await get_current_session(request)
    if not session:
        return {"error": "Not authenticated"}
    
    # Always return overall for now (simplified)
    models = leaderboard_data.get("overall", DEFAULT_LEADERBOARD["overall"])
    last_updated = leaderboard_data.get("last_updated", "Unknown")
    
    return {
        "category": "overall",
        "models": models,
        "last_updated": last_updated,
        "timestamp": int(time.time())
    }

@app.post("/api/leaderboard/refresh")
async def refresh_leaderboard(request: Request):
    """Refresh leaderboard data by fetching from LMArena using browser automation"""
    session = await get_current_session(request)
    if not session:
        return {"error": "Not authenticated", "success": False}
    
    try:
        success = await fetch_leaderboard_with_browser()
        
        if success:
            models = leaderboard_data.get("overall", [])
            last_updated = leaderboard_data.get("last_updated", "Unknown")
            return {
                "success": True,
                "message": f"Leaderboard refreshed with {len(models)} models",
                "models": models,
                "last_updated": last_updated
            }
        else:
            # Return cached data on failure
            models = leaderboard_data.get("overall", DEFAULT_LEADERBOARD["overall"])
            last_updated = leaderboard_data.get("last_updated", "Unknown")
            return {
                "success": False,
                "message": "Failed to fetch fresh data, showing cached results",
                "models": models,
                "last_updated": last_updated
            }
    except Exception as e:
        await add_log(f"❌ Leaderboard refresh error: {e}", "ERROR")
        return {
            "success": False,
            "message": f"Error: {str(e)}",
            "models": leaderboard_data.get("overall", DEFAULT_LEADERBOARD["overall"]),
            "last_updated": leaderboard_data.get("last_updated", "Unknown")
        }

@app.post("/update-generation-settings")
async def update_generation_settings(
    request: Request,
    default_temperature: Optional[float] = Form(None),
    default_top_p: Optional[float] = Form(None),
    default_max_tokens: Optional[int] = Form(None),
    default_presence_penalty: Optional[float] = Form(None),
    default_frequency_penalty: Optional[float] = Form(None)
):
    """Update generation parameters"""
    session = await get_current_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=303)
    
    config = get_config()
    
    # Update generation settings if provided
    if default_temperature is not None:
        config["default_temperature"] = max(0.0, min(default_temperature, 2.0))
    if default_top_p is not None:
        config["default_top_p"] = max(0.0, min(default_top_p, 1.0))
    if default_max_tokens is not None:
        config["default_max_tokens"] = max(1, min(default_max_tokens, 128000))
    if default_presence_penalty is not None:
        config["default_presence_penalty"] = max(-2.0, min(default_presence_penalty, 2.0))
    if default_frequency_penalty is not None:
        config["default_frequency_penalty"] = max(-2.0, min(default_frequency_penalty, 2.0))
        
    save_config(config)
    
    return RedirectResponse(url="/dashboard?success=generation_settings_updated", status_code=303)

@app.post("/update-collection-settings")
async def update_collection_settings(
    request: Request,
    token_collect_count: Optional[int] = Form(None),
    token_collect_delay: Optional[int] = Form(None),
    chunk_size: Optional[int] = Form(None),
    chunk_rotation_limit: Optional[int] = Form(None),
    default_presence_penalty: Optional[float] = Form(None),
    default_frequency_penalty: Optional[float] = Form(None)
):
    """Update system settings (collection & advanced)"""
    session = await get_current_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=303)
    
    # Force reload to get fresh config from disk
    config = get_config(force_reload=True)
    
    # Update collection settings if provided
    if token_collect_count is not None:
        config["token_collect_count"] = max(1, min(token_collect_count, 50))
        debug_print(f"⚙️ Updated token_collect_count: {config['token_collect_count']}")
    if token_collect_delay is not None:
        config["token_collect_delay"] = max(1, min(token_collect_delay, 60))
        debug_print(f"⚙️ Updated token_collect_delay: {config['token_collect_delay']}")
        
    # Update advanced settings if provided
    if chunk_size is not None:
        config["chunk_size"] = max(1000, chunk_size)
        debug_print(f"⚙️ Updated chunk_size: {config['chunk_size']:,}")
    if chunk_rotation_limit is not None:
        config["chunk_rotation_limit"] = max(1, chunk_rotation_limit)
        debug_print(f"⚙️ Updated chunk_rotation_limit: {config['chunk_rotation_limit']}")
    if default_presence_penalty is not None:
        config["default_presence_penalty"] = max(-2.0, min(default_presence_penalty, 2.0))
    if default_frequency_penalty is not None:
        config["default_frequency_penalty"] = max(-2.0, min(default_frequency_penalty, 2.0))
        
    save_config(config)
    
    return RedirectResponse(url="/dashboard?success=settings_updated", status_code=303)

@app.post("/update-profile")
async def update_profile(
    request: Request,
    profile_name: Optional[str] = Form(None),
    profile_avatar: Optional[str] = Form(None)
):
    """Update user profile settings"""
    session = await get_current_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=303)
    
    config = get_config()
    
    # Update profile name (sanitize and limit length)
    if profile_name is not None:
        clean_name = profile_name.strip()[:30]
        if clean_name:
            config["profile_name"] = clean_name
    
    # Update profile avatar (limit to 2 chars for emoji support)
    if profile_avatar is not None:
        clean_avatar = profile_avatar.strip()[:2]
        if clean_avatar:
            config["profile_avatar"] = clean_avatar
    
    save_config(config)
    
    return RedirectResponse(url="/dashboard?success=profile_updated", status_code=303)

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
                    // Look for Turnstile iframe within the dialog to get click coordinates
                    const iframe = dialog.querySelector('iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"]');
                    if (iframe) {
                        const rect = iframe.getBoundingClientRect();
                        if (rect.width > 0 && rect.height > 0) {
                            return { found: true, type: 'security_dialog', x: rect.x + 35, y: rect.y + rect.height / 2 };
                        }
                    }
                    // No iframe found, return without coordinates
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
    
    # Brief wait for Turnstile to render
    await asyncio.sleep(0.5)
    
    # Try multiple methods to click the Turnstile checkbox
    clicked = False
    
    for attempt in range(3):  # Reduced from 5 to 3 attempts
        if clicked:
            break
        await add_log(f"🛡️ [{context}] Click attempt {attempt + 1}/3...", "DEBUG")
        
        # Method 1: Click via bounding box from JS evaluation (refresh coordinates on each attempt)
        if not clicked:
            try:
                fresh_info = await page.evaluate("""
                    () => {
                        // Find Turnstile iframe
                        const iframes = document.querySelectorAll('iframe[src*="challenges.cloudflare.com"]');
                        for (const iframe of iframes) {
                            const rect = iframe.getBoundingClientRect();
                            if (rect.width > 0 && rect.height > 0) {
                                // Click at checkbox position (left side of frame)
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
                    await add_log(f"✅ [{context}] Clicked at ({int(x)}, {int(y)}) via JS evaluation!", "SUCCESS")
                    clicked = True
            except Exception as e:
                await add_log(f"⚠️ [{context}] JS evaluation click failed: {e}", "DEBUG")
        
        # Method 2: Use initial coordinates if we have them
        if not clicked and turnstile_present.get('x') and turnstile_present.get('y'):
            try:
                x, y = turnstile_present['x'], turnstile_present['y']
                await page.mouse.move(x, y, steps=5)
                await asyncio.sleep(0.2)
                await page.mouse.click(x, y)
                await add_log(f"✅ [{context}] Clicked at ({int(x)}, {int(y)}) via initial coords!", "SUCCESS")
                clicked = True
            except Exception as e:
                await add_log(f"⚠️ [{context}] Initial coords click failed: {e}", "DEBUG")
        
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
                        
                        # Try clicking the label or checkbox container
                        label = await frame.query_selector('label, .cb-lb, .ctp-checkbox-label')
                        if label:
                            await label.click()
                            await add_log(f"✅ [{context}] Clicked label in frame!", "SUCCESS")
                            clicked = True
                            break
                        
                        # Get frame element bounding box from parent page
                        frame_element = await page.query_selector(f'iframe[src*="challenges.cloudflare.com"]')
                        if frame_element:
                            frame_box = await frame_element.bounding_box()
                            if frame_box:
                                # Click at the checkbox position (left side of frame, vertically centered)
                                # Turnstile checkbox is typically at x=35 from left edge
                                click_x = frame_box['x'] + 35
                                click_y = frame_box['y'] + frame_box['height'] / 2
                                await page.mouse.move(click_x, click_y, steps=5)
                                await asyncio.sleep(0.2)
                                await page.mouse.click(click_x, click_y)
                                await add_log(f"✅ [{context}] Clicked frame element at ({int(click_x)}, {int(click_y)})!", "SUCCESS")
                                clicked = True
                                break
                        
                        # Fallback: Try clicking body
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
        await add_log(f"⚠️ [{context}] Could not click Turnstile after 3 attempts", "WARN")
        return False
    
    # Wait for Turnstile verification to complete (reduced to 8s max for speed)
    await add_log(f"⏳ [{context}] Waiting for Turnstile verification...", "DEBUG")
    
    for wait_attempt in range(8):  # Wait up to 8 seconds (reduced from 15)
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
            return True
        
        if wait_attempt == 7:
            await add_log(f"⚠️ [{context}] Turnstile still visible after 8s", "WARN")
    
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
                
                # Navigate to LMArena - Try arena mode first (simpler, more reliable for auth)
                # Arena mode triggers auth on first interaction without needing model selection
                await add_log(f"🌐 Navigating to LMArena Arena mode...", "DEBUG")
                await collection_page.goto(
                    "https://lmarena.ai/", 
                    wait_until="domcontentloaded",
                    timeout=60000
                )
                
                # Wait for page to load and React to hydrate
                await asyncio.sleep(2)
                
                # CRITICAL: Clear localStorage and sessionStorage to ensure Terms dialog appears
                # If terms acceptance is stored, the dialog won't show!
                try:
                    await collection_page.evaluate("""
                        () => {
                            localStorage.clear();
                            sessionStorage.clear();
                        }
                    """)
                    await add_log("🧹 Cleared localStorage/sessionStorage", "DEBUG")
                    # No reload needed - storage is cleared for this page context
                except Exception as clear_err:
                    await add_log(f"⚠️ Storage clear error: {clear_err}", "DEBUG")
                
                # Check page state
                current_title = await collection_page.title()
                current_url = collection_page.url
                await add_log(f"📄 Page title: {current_title}", "DEBUG")
                await add_log(f"📄 Page URL: {current_url}", "DEBUG")
                
                # Debug: Log what elements are on the page
                page_debug = await collection_page.evaluate("""
                    () => {
                        const info = {
                            title: document.title,
                            url: location.href,
                            buttons: [],
                            textareas: [],
                            dialogs: [],
                            iframes: []
                        };
                        
                        // Check for buttons
                        document.querySelectorAll('button').forEach(b => {
                            if (b.offsetParent !== null) { // visible only
                                info.buttons.push(b.textContent.trim().substring(0, 50));
                            }
                        });
                        
                        // Check for textareas
                        document.querySelectorAll('textarea').forEach(t => {
                            info.textareas.push({
                                placeholder: t.placeholder,
                                visible: t.offsetParent !== null
                            });
                        });
                        
                        // Check for dialogs
                        document.querySelectorAll('[role="dialog"]').forEach(d => {
                            info.dialogs.push(d.textContent.substring(0, 100));
                        });
                        
                        // Check for iframes
                        document.querySelectorAll('iframe').forEach(f => {
                            info.iframes.push(f.src.substring(0, 80));
                        });
                        
                        return info;
                    }
                """)
                await add_log(f"🔍 Page debug - Buttons: {page_debug.get('buttons', [])[:5]}", "DEBUG")
                await add_log(f"🔍 Page debug - Textareas: {page_debug.get('textareas', [])}", "DEBUG")
                await add_log(f"🔍 Page debug - Dialogs: {len(page_debug.get('dialogs', []))}", "DEBUG")
                
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
                    
                    # Brief wait for UI (React hydration)
                    await asyncio.sleep(1)
                    
                    model_selected = False
                    try:
                        # COMPREHENSIVE model selection using JavaScript
                        # This handles various UI layouts LMArena might use
                        model_selected = await collection_page.evaluate("""
                            async () => {
                                // Helper to wait
                                const wait = (ms) => new Promise(r => setTimeout(r, ms));
                                
                                // Method 1: Look for dropdown/combobox button with model-related text
                                const dropdownSelectors = [
                                    'button[aria-haspopup="listbox"]',
                                    'button[aria-haspopup="menu"]',
                                    'button[role="combobox"]',
                                    '[data-testid*="model"]',
                                    '[class*="model-select"]',
                                    '[class*="ModelSelect"]',
                                    // Shadcn/Radix UI patterns
                                    'button[data-state]',
                                    // MUI patterns
                                    '[class*="MuiSelect"]',
                                    // Generic dropdown patterns
                                    '.select-trigger',
                                    '.dropdown-trigger'
                                ];
                                
                                for (const selector of dropdownSelectors) {
                                    const elements = document.querySelectorAll(selector);
                                    for (const el of elements) {
                                        const text = el.textContent?.toLowerCase() || '';
                                        const placeholder = el.getAttribute('placeholder')?.toLowerCase() || '';
                                        const ariaLabel = el.getAttribute('aria-label')?.toLowerCase() || '';
                                        
                                        // Check if this looks like a model selector
                                        if (text.includes('select') || text.includes('model') || text.includes('choose') ||
                                            placeholder.includes('model') || ariaLabel.includes('model') ||
                                            text.includes('gpt') || text.includes('claude') || text.includes('gemini')) {
                                            console.log('Found model dropdown:', el.textContent);
                                            el.click();
                                            await wait(800);
                                            
                                            // Now look for options in the opened dropdown
                                            const optionSelectors = [
                                                '[role="option"]',
                                                '[role="menuitem"]',
                                                '[role="listbox"] > *',
                                                '[data-radix-collection-item]',
                                                '.dropdown-item',
                                                '.select-item',
                                                '[class*="Option"]',
                                                '[class*="option"]'
                                            ];
                                            
                                            for (const optSelector of optionSelectors) {
                                                const options = document.querySelectorAll(optSelector);
                                                if (options.length > 0) {
                                                    // Click first available option
                                                    console.log('Found option to click:', options[0].textContent);
                                                    options[0].click();
                                                    return true;
                                                }
                                            }
                                            
                                            // Fallback: look for any clickable element with model names
                                            const modelNames = ['gpt', 'claude', 'gemini', 'llama', 'mistral', 'qwen', 'deepseek'];
                                            const allClickables = document.querySelectorAll('button, [role="option"], [role="menuitem"], div[tabindex], li');
                                            for (const clickable of allClickables) {
                                                const cText = clickable.textContent?.toLowerCase() || '';
                                                if (modelNames.some(m => cText.includes(m))) {
                                                    console.log('Found model option:', clickable.textContent);
                                                    clickable.click();
                                                    return true;
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                // Method 2: Direct search for any element showing model names (already visible)
                                const modelNames = ['gpt-4', 'gpt-3.5', 'claude', 'gemini', 'llama', 'mistral'];
                                const allElements = document.querySelectorAll('button, a, div[role="button"], [class*="model"]');
                                for (const el of allElements) {
                                    const text = el.textContent?.toLowerCase() || '';
                                    if (modelNames.some(m => text.includes(m)) && el.offsetParent !== null) {
                                        // This element contains a model name and is visible
                                        console.log('Found visible model element:', el.textContent);
                                        el.click();
                                        return true;
                                    }
                                }
                                
                                // Method 3: Look for "Select a model" text anywhere
                                const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
                                while (walker.nextNode()) {
                                    const node = walker.currentNode;
                                    if (node.textContent?.toLowerCase().includes('select a model') || 
                                        node.textContent?.toLowerCase().includes('choose a model')) {
                                        // Click the parent element
                                        const parent = node.parentElement;
                                        if (parent && parent.click) {
                                            console.log('Clicking "Select a model" parent');
                                            parent.click();
                                            await wait(800);
                                            
                                            // Look for options
                                            const options = document.querySelectorAll('[role="option"], [role="menuitem"]');
                                            if (options.length > 0) {
                                                options[0].click();
                                                return true;
                                            }
                                        }
                                    }
                                }
                                
                                return false;
                            }
                        """)
                        
                        if model_selected:
                            await add_log("✅ Selected model via JS!", "SUCCESS")
                            await asyncio.sleep(1)
                        else:
                            # Fallback: Try Playwright selectors
                            model_selector_btn = await collection_page.query_selector(
                                'button[aria-haspopup="listbox"], '
                                'button:has-text("Select a model"), '
                                'button:has-text("Choose"), '
                                '[data-testid="model-selector"], '
                                '.model-selector'
                            )
                            
                            if model_selector_btn:
                                await add_log("📋 Found model selector via Playwright, clicking...", "DEBUG")
                                await model_selector_btn.click(timeout=3000)
                                await asyncio.sleep(1)
                                
                                # Look for a model option
                                model_option = await collection_page.query_selector(
                                    '[role="option"], '
                                    '[role="menuitem"], '
                                    '[role="listbox"] button'
                                )
                                
                                if model_option:
                                    await model_option.click(timeout=3000)
                                    model_selected = True
                                    await add_log("✅ Selected model option!", "SUCCESS")
                                    await asyncio.sleep(1)
                            
                    except Exception as model_err:
                        await add_log(f"⚠️ Model selection error: {model_err}", "DEBUG")
                    
                    if not model_selected:
                        await add_log("⚠️ Could not select model - OK for Arena mode (uses random models)", "DEBUG")
                    else:
                        await add_log("✅ Model selected!", "SUCCESS")
                    
                    # ============================================================
                    # STEP 2: Brief wait for page scripts to initialize
                    # ============================================================
                    await asyncio.sleep(1)
                    
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
                                        
                                        # Quick check for any Turnstile verification
                                        await add_log("⏳ Waiting for Turnstile to complete (if any)...", "DEBUG")
                                        for turnstile_wait in range(5):  # Reduced from 10 to 5 seconds
                                            turnstile_status = await collection_page.evaluate("""
                                                () => {
                                                    // Check for Turnstile iframes
                                                    const iframes = document.querySelectorAll('iframe[src*="challenges.cloudflare.com"]');
                                                    for (const iframe of iframes) {
                                                        const rect = iframe.getBoundingClientRect();
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
                                            if turnstile_wait == 4:
                                                await add_log("⚠️ Turnstile still active after 5s, proceeding anyway", "WARN")
                                        
                                        for attempt in range(5):  # 5 attempts
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
                    # NOTE: This API may require a Turnstile response token to work
                    # ============================================================
                    if not found_auth_token["value"]:
                        await add_log("🔄 No token yet, trying direct API call to sign-up...", "DEBUG")
                        try:
                            # First, try to get the Turnstile response token if available
                            signup_result = await collection_page.evaluate("""
                                async () => {
                                    try {
                                        // Try to find turnstile response in the page
                                        let turnstileResponse = null;
                                        
                                        // Method 1: Check for turnstile widget response
                                        const turnstileWidget = document.querySelector('[name="cf-turnstile-response"]');
                                        if (turnstileWidget && turnstileWidget.value) {
                                            turnstileResponse = turnstileWidget.value;
                                        }
                                        
                                        // Method 2: Try window.turnstile if available
                                        if (!turnstileResponse && window.turnstile) {
                                            const widgets = window.turnstile.getWidgets();
                                            if (widgets && widgets.length > 0) {
                                                turnstileResponse = window.turnstile.getResponse(widgets[0]);
                                            }
                                        }
                                        
                                        // Build request body
                                        const body = {};
                                        if (turnstileResponse) {
                                            body.turnstileResponse = turnstileResponse;
                                            body['cf-turnstile-response'] = turnstileResponse;
                                        }
                                        
                                        const response = await fetch('/nextjs-api/sign-up', {
                                            method: 'POST',
                                            headers: {
                                                'Content-Type': 'application/json',
                                            },
                                            body: Object.keys(body).length > 0 ? JSON.stringify(body) : undefined,
                                            credentials: 'include'
                                        });
                                        
                                        let responseText = '';
                                        try {
                                            responseText = await response.text();
                                        } catch (e) {}
                                        
                                        return { 
                                            status: response.status, 
                                            ok: response.ok,
                                            hadTurnstile: !!turnstileResponse,
                                            response: responseText.substring(0, 200)
                                        };
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
                await asyncio.sleep(0.5)
                
                # Poll for the auth cookie (network response is usually fastest)
                auth_cookie = None
                token_collected_via_network = False  # Track if we collected via network response
                max_wait = 12  # Reduced from 20 - token usually arrives quickly
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
                            token_collected_via_network = True  # Mark as collected
                            
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
                                    await collection_page.goto("https://lmarena.ai/", wait_until="domcontentloaded", timeout=60000)
                                    await add_log(f"✅ Page reloaded, ready for next collection", "DEBUG")
                                except Exception as reload_err:
                                    await add_log(f"⚠️ Reload error: {reload_err}", "WARN")
                        else:
                            await add_log(f"⚠️ Token already exists, skipping", "WARN")
                            token_collected_via_network = True  # Still mark as handled
                        
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
                                await collection_page.goto("https://lmarena.ai/", wait_until="domcontentloaded", timeout=30000)
                            except Exception as reload_err:
                                await add_log(f"⚠️ Reload error: {reload_err}", "WARN")
                    else:
                        await add_log(f"⚠️ Duplicate token found, will retry...", "WARN")
                        i -= 1
                elif token_collected_via_network:
                    # Token was already collected via network response, skip this warning
                    pass
                else:
                    await add_log(f"⚠️ No auth cookie found after {max_wait}s on attempt {i + 1}", "WARN")
                    token_collection_status["errors"].append(f"No cookie on attempt {i + 1}")
                    
                    # Log detailed page state for debugging
                    try:
                        page_state = await collection_page.evaluate("""
                            () => ({
                                url: location.href,
                                title: document.title,
                                dialogCount: document.querySelectorAll('[role="dialog"]').length,
                                iframeCount: document.querySelectorAll('iframe').length,
                                buttonTexts: Array.from(document.querySelectorAll('button')).slice(0,10).map(b => b.textContent.trim().substring(0,30)),
                                cookies: document.cookie,
                                localStorageKeys: Object.keys(localStorage).slice(0,10)
                            })
                        """)
                        await add_log(f"🔍 Page state at failure: URL={page_state.get('url', 'N/A')}", "DEBUG")
                        await add_log(f"🔍 Dialogs: {page_state.get('dialogCount', 0)}, Iframes: {page_state.get('iframeCount', 0)}", "DEBUG")
                        await add_log(f"🔍 Buttons: {page_state.get('buttonTexts', [])[:5]}", "DEBUG")
                    except Exception as state_err:
                        await add_log(f"⚠️ Could not get page state: {state_err}", "DEBUG")
                    
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
    global active_generations, total_tokens_generated
    
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
        default_pres_pen = config.get("default_presence_penalty", 0.0)
        default_freq_pen = config.get("default_frequency_penalty", 0.0)
        
        # Frontend (SillyTavern, etc.) can override these by sending them in the request
        temperature = body.get("temperature") if body.get("temperature") is not None else default_temp
        top_p = body.get("top_p") if body.get("top_p") is not None else default_top_p
        max_tokens = body.get("max_tokens") if body.get("max_tokens") is not None else default_max_tokens
        presence_penalty = body.get("presence_penalty") if body.get("presence_penalty") is not None else default_pres_pen
        frequency_penalty = body.get("frequency_penalty") if body.get("frequency_penalty") is not None else default_freq_pen
        
        # Build generation_params dict (will be added to payload later)
        generation_params = {
            "temperature": temperature,
            "top_p": top_p,
            "max_new_tokens": max_tokens,
            "presence_penalty": presence_penalty,
            "frequency_penalty": frequency_penalty
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
            # Initialize if missing (for migration safety)
            if model_public_name not in model_usage_stats:
                model_usage_stats[model_public_name] = {"count": 0, "tokens": 0, "last_used": 0}
            elif isinstance(model_usage_stats[model_public_name], int):
                # Auto-migrate on the fly if we hit an old int
                model_usage_stats[model_public_name] = {"count": model_usage_stats[model_public_name], "tokens": 0, "last_used": 0}
            
            # Update stats
            model_usage_stats[model_public_name]["count"] += 1
            model_usage_stats[model_public_name]["last_used"] = int(time.time())
            # Estimate tokens (chars / 4 is a rough approximation for prompt)
            # We'll add response tokens later if possible, but for now prompt tokens is better than nothing
            estimated_prompt_tokens = len(json.dumps(messages)) // 4
            model_usage_stats[model_public_name]["tokens"] += estimated_prompt_tokens
            
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
        # Use config values for chunking
        config = get_config()
        chunk_size = config.get("chunk_size", 110000)
        chunk_rotation_limit = config.get("chunk_rotation_limit", 5)
        
        chunks = []
        if len(prompt) > chunk_size:
            debug_print(f"✂️ Prompt length {len(prompt)} > {chunk_size}. Splitting into chunks...")
            for i in range(0, len(prompt), chunk_size):
                chunks.append(prompt[i:i+chunk_size])
            debug_print(f"🧩 Split into {len(chunks)} chunks")
        else:
            chunks.append(prompt)
            
        total_chunks = len(chunks)
        url = "https://lmarena.ai/nextjs-api/stream/create-evaluation"
        
        # Local history for this multi-turn request
        local_messages = []

        def build_fake_history_payload(all_chunks, session_id):
            """
            Build a single payload with all chunks bundled as fake chat history.
            Only the LAST chunk becomes the actual userMessage.
            All previous chunks become fake user/assistant pairs in history.
            """
            fake_history = []
            parent_ids = []
            
            # Process all chunks EXCEPT the last one as fake history
            for idx, chunk_content in enumerate(all_chunks[:-1]):
                # Generate IDs for this fake turn
                fake_user_id = str(uuid7())
                fake_assistant_id = str(uuid7())
                
                # Add chunk number indicator
                chunk_label = f"[CONTEXT PART {idx + 1}/{len(all_chunks)}]\n\n"
                
                # Fake user message (the chunk content)
                fake_user_msg = {
                    "id": fake_user_id,
                    "role": "user",
                    "content": chunk_label + chunk_content,
                    "experimental_attachments": [],
                    "parentMessageIds": parent_ids.copy(),
                    "participantPosition": "a",
                    "modelId": None,
                    "evaluationSessionId": session_id,
                    "status": "success",
                    "failureReason": None
                }
                fake_history.append(fake_user_msg)
                
                # Fake assistant acknowledgment
                fake_assistant_msg = {
                    "id": fake_assistant_id,
                    "role": "assistant",
                    "content": ".",  # Simple acknowledgment
                    "experimental_attachments": [],
                    "parentMessageIds": [fake_user_id],
                    "participantPosition": "a",
                    "modelId": model_id,
                    "evaluationSessionId": session_id,
                    "status": "success",
                    "failureReason": None
                }
                fake_history.append(fake_assistant_msg)
                
                # Update parent for next iteration
                parent_ids = [fake_assistant_id]
            
            # Now build the ACTUAL payload with the LAST chunk
            last_chunk = all_chunks[-1]
            payload_id = str(uuid7())
            user_msg_id = str(uuid7())
            model_msg_id = str(uuid7())
            
            # Add instruction to the last chunk if we had multiple chunks
            if len(all_chunks) > 1:
                final_content = f"[FINAL PART {len(all_chunks)}/{len(all_chunks)} - You now have all the context. Please respond to the user's request.]\n\n" + last_chunk
            else:
                final_content = last_chunk
            
            payload = {
                "id": payload_id,
                "mode": "direct",
                "modelAId": model_id,
                "userMessageId": user_msg_id,
                "modelAMessageId": model_msg_id,
                "userMessage": {
                    "content": final_content,
                    "experimental_attachments": experimental_attachments,
                    "parentMessageIds": parent_ids,
                },
                "modality": "chat",
                "parameters": generation_params,
                "recaptchaV3Token": "03AFcWeA..."
            }
            
            # Inject real reCAPTCHA token if available
            config = get_config()
            if config.get("recaptcha_token"):
                payload["recaptchaV3Token"] = config.get("recaptcha_token")
            
            # Add fake history to payload
            if fake_history:
                payload["messages"] = fake_history
            
            debug_print(f"📦 Built FAKE HISTORY payload: {len(all_chunks)-1} history pairs + 1 final message")
            debug_print(f"📊 Total fake history messages: {len(fake_history)}")
            
            return payload

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
                global total_tokens_generated  # Declare at top of function
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
                    
                    # ============================================================
                    # FAKE HISTORY MODE - Send all chunks in ONE request!
                    # ============================================================
                    if FAKE_HISTORY_MODE and total_chunks > 1:
                        debug_print(f"📜 FAKE HISTORY MODE: Bundling {total_chunks} chunks into single request")
                        
                        # Get headers and session
                        sticky_key = f"{api_key_str}:{model_public_name}"
                        if STICKY_SESSIONS and sticky_key in sticky_session_ids:
                            data = sticky_session_ids[sticky_key]
                            current_session_id = data["session_id"]
                            current_headers = data["headers"]
                            debug_print(f"📎 Reusing Sticky Session ID: {current_session_id}")
                        else:
                            current_headers = get_request_headers()
                            current_session_id = str(uuid7())
                            if STICKY_SESSIONS:
                                sticky_session_ids[sticky_key] = {
                                    "session_id": current_session_id,
                                    "headers": current_headers
                                }
                            debug_print(f"📎 Created New Session ID: {current_session_id}")
                        
                        # Small thinking delay
                        think_delay = random.uniform(0.5, 1.5)
                        debug_print(f"🤔 Thinking delay: {think_delay:.2f}s")
                        await asyncio.sleep(think_delay)
                        
                        # Build the fake history payload
                        payload = build_fake_history_payload(chunks, current_session_id)
                        
                        # Prepare headers
                        chunk_headers = {
                            "Cookie": current_headers.get("Cookie"),
                            "Content-Type": current_headers.get("Content-Type"),
                            "Referer": current_headers.get("Referer"),
                            "Origin": current_headers.get("Origin"),
                        }
                        chunk_headers = {k: v for k, v in chunk_headers.items() if v is not None}
                        
                        # Log token info
                        token_match = re.search(r'arena-auth-prod-v1=([^;]+)', chunk_headers.get("Cookie", ""))
                        token_display = "Unknown"
                        if token_match:
                            current_token = token_match.group(1)
                            try:
                                _tokens = get_config().get("auth_tokens", [])
                                if current_token in _tokens:
                                    token_display = f"#{_tokens.index(current_token) + 1}"
                            except: pass
                        
                        debug_print(f"📋 SINGLE REQUEST | Token {token_display} | Session: {current_session_id}")
                        
                        current_response_text = ""
                        
                        # Retry loop for the single request
                        for attempt in range(5):
                            try:
                                async with AsyncSession(impersonate=impersonate_target) as client:
                                    response = await client.post(url, json=payload, headers=chunk_headers, timeout=180, stream=True)
                                    
                                    if response.status_code in [429, 401, 403, 400]:
                                        error_type = "Rate Limit" if response.status_code == 429 else "Auth/Bad Request Error"
                                        debug_print(f"⚠️ {response.status_code} ({error_type})")
                                        
                                        if STICKY_SESSIONS and sticky_key in sticky_session_ids:
                                            del sticky_session_ids[sticky_key]
                                        
                                        if attempt < 4:
                                            debug_print(f"♻️ Rotating token and retrying (Attempt {attempt+2}/5)...")
                                            await asyncio.sleep(2 + attempt)
                                            current_headers = get_request_headers()
                                            current_session_id = str(uuid7())
                                            chunk_headers["Cookie"] = current_headers.get("Cookie")
                                            # Rebuild payload with new session ID
                                            payload = build_fake_history_payload(chunks, current_session_id)
                                            if STICKY_SESSIONS:
                                                sticky_session_ids[sticky_key] = {
                                                    "session_id": current_session_id,
                                                    "headers": current_headers
                                                }
                                            continue
                                        raise HTTPException(status_code=response.status_code, detail=f"Upstream error: {response.status_code}")
                                    
                                    if response.status_code >= 400:
                                        raise HTTPException(status_code=response.status_code, detail=f"Upstream error: {response.status_code}")
                                    
                                    # Stream the response
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
                                                yield f"data: {fast_json_dumps(chunk_response)}\n\n"
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
                                                yield f"data: {fast_json_dumps(final_chunk)}\n\n"
                                            except: pass
                                        elif line.startswith("a3:"):
                                            error_data = line[3:]
                                            try:
                                                error_message = json.loads(error_data)
                                                error_str = str(error_message).lower()
                                                print(f"  ❌ Error in stream: {error_message}")
                                                
                                                # Check for rate limit errors
                                                rate_limit_keywords = [
                                                    "resource exhausted", "rate limit", "429", "too many requests",
                                                    "quota exceeded", "capacity", "overloaded", "try again later"
                                                ]
                                                is_rate_limit = any(kw in error_str for kw in rate_limit_keywords)
                                                
                                                if is_rate_limit and attempt < 4:
                                                    print(f"  🔄 Detected upstream rate limit! Will rotate token and retry...")
                                                    raise UpstreamRateLimitError(error_message)
                                                
                                                error_chunk = {
                                                    "error": {
                                                        "message": str(error_message),
                                                        "type": "api_error",
                                                        "code": 500
                                                    }
                                                }
                                                yield f"data: {fast_json_dumps(error_chunk)}\n\n"
                                            except UpstreamRateLimitError:
                                                raise
                                            except: pass
                                    
                                    # Success - count tokens and finish
                                    try:
                                        enc = tiktoken.get_encoding("cl100k_base")
                                        stream_tokens = len(enc.encode(current_response_text))
                                        total_tokens_generated += stream_tokens
                                        if model_public_name in model_usage_stats:
                                            model_usage_stats[model_public_name]["tokens"] += stream_tokens
                                        add_activity(model_public_name, stream_tokens, "success")
                                        debug_print(f"✅ FAKE HISTORY stream complete | Tokens: {stream_tokens}")
                                    except Exception:
                                        est_tokens = len(current_response_text) // 4
                                        total_tokens_generated += est_tokens
                                        if model_public_name in model_usage_stats:
                                            model_usage_stats[model_public_name]["tokens"] += est_tokens
                                        add_activity(model_public_name, est_tokens, "success")
                                        debug_print(f"✅ FAKE HISTORY stream complete | Tokens: ~{est_tokens}")
                                    
                                    yield "data: [DONE]\n\n"
                                    debug_print(f"✅ Stream completed (FAKE HISTORY MODE)")
                                    return  # Exit the generator
                                    
                            except UpstreamRateLimitError as e:
                                print(f"⚠️ Upstream rate limit: {e}")
                                if STICKY_SESSIONS and sticky_key in sticky_session_ids:
                                    del sticky_session_ids[sticky_key]
                                retry_delay = 3 + attempt * 2
                                debug_print(f"🔄 Rotating token and waiting {retry_delay}s (Attempt {attempt+2}/5)...")
                                await asyncio.sleep(retry_delay)
                                current_headers = get_request_headers()
                                current_session_id = str(uuid7())
                                chunk_headers["Cookie"] = current_headers.get("Cookie")
                                payload = build_fake_history_payload(chunks, current_session_id)
                                if STICKY_SESSIONS:
                                    sticky_session_ids[sticky_key] = {
                                        "session_id": current_session_id,
                                        "headers": current_headers
                                    }
                                continue
                            except (HTTPError, Timeout, RequestsError, ConnectionError) as e:
                                print(f"❌ Stream error: {e}")
                                if attempt < 4:
                                    await asyncio.sleep(2)
                                    current_headers = get_request_headers()
                                    current_session_id = str(uuid7())
                                    chunk_headers["Cookie"] = current_headers.get("Cookie")
                                    payload = build_fake_history_payload(chunks, current_session_id)
                                    continue
                                error_chunk = {"error": {"message": f"Upstream error: {str(e)}", "type": "upstream_error", "code": 502}}
                                yield f"data: {fast_json_dumps(error_chunk)}\n\n"
                                return
                        
                        # If we exhausted all retries
                        error_chunk = {"error": {"message": "All retry attempts failed", "type": "upstream_error", "code": 502}}
                        yield f"data: {fast_json_dumps(error_chunk)}\n\n"
                        return
                    
                    # ============================================================
                    # LEGACY MODE - Sequential chunk sending (when FAKE_HISTORY_MODE is False or single chunk)
                    # ============================================================
                    for i, chunk in enumerate(chunks):
                        # --- ROTATION LOGIC ---
                        is_new_session = False
                        if i % chunk_rotation_limit == 0:
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
                                                    yield f"data: {fast_json_dumps(chunk_response)}\n\n"
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
                                                    yield f"data: {fast_json_dumps(final_chunk)}\n\n"
                                                except: pass
                                            elif line.startswith("a3:"):
                                                error_data = line[3:]
                                                try:
                                                    error_message = json.loads(error_data)
                                                    error_str = str(error_message).lower()
                                                    print(f"  ❌ Error in stream: {error_message}")
                                                    
                                                    # Check if this is a rate limit / resource exhausted error
                                                    rate_limit_keywords = [
                                                        "resource exhausted", "rate limit", "429", "too many requests",
                                                        "quota exceeded", "capacity", "overloaded", "try again later"
                                                    ]
                                                    is_rate_limit = any(kw in error_str for kw in rate_limit_keywords)
                                                    
                                                    if is_rate_limit and attempt < 4:
                                                        print(f"  🔄 Detected upstream rate limit! Will rotate token and retry...")
                                                        raise UpstreamRateLimitError(error_message)
                                                    
                                                    # Not a rate limit or out of retries - yield error to client
                                                    error_chunk = {
                                                        "error": {
                                                            "message": str(error_message),
                                                            "type": "api_error",
                                                            "code": 500
                                                        }
                                                    }
                                                    yield f"data: {fast_json_dumps(error_chunk)}\n\n"
                                                except UpstreamRateLimitError:
                                                    raise  # Re-raise to be caught by outer retry loop
                                                except: pass
                                        
                                        # Update history (though not strictly needed for final chunk unless we want to save it)
                                        user_msg["status"] = "success"
                                        model_msg["content"] = current_response_text
                                        model_msg["status"] = "success"
                                        local_messages.append(user_msg)
                                        local_messages.append(model_msg)
                                        
                                        # Count tokens for streaming response
                                        try:
                                            enc = tiktoken.get_encoding("cl100k_base")
                                            stream_tokens = len(enc.encode(current_response_text))
                                            total_tokens_generated += stream_tokens
                                            # Update per-model token count
                                            if model_public_name in model_usage_stats:
                                                model_usage_stats[model_public_name]["tokens"] += stream_tokens
                                            # Add to activity log
                                            add_activity(model_public_name, stream_tokens, "success")
                                            debug_print(f"✅ Stream complete | Tokens: {stream_tokens}")
                                        except Exception:
                                            est_tokens = len(current_response_text) // 4
                                            total_tokens_generated += est_tokens
                                            if model_public_name in model_usage_stats:
                                                model_usage_stats[model_public_name]["tokens"] += est_tokens
                                            add_activity(model_public_name, est_tokens, "success")
                                            debug_print(f"✅ Stream complete | Tokens: ~{est_tokens}")
                                                
                                        yield "data: [DONE]\n\n"
                                        debug_print(f"✅ Stream completed")
                                    
                                    # Success - break retry loop
                                    break
                            
                            except ImpersonateError as e:
                                print(f"⚠️ Impersonation error: {e}. Falling back to chrome120.")
                                impersonate_target = "chrome120"
                                continue # Retry immediately with new target

                            except UpstreamRateLimitError as e:
                                # Upstream provider (Google, OpenAI, etc.) hit rate limit
                                print(f"⚠️ Upstream rate limit on Chunk {i+1}: {e}")
                                
                                if STICKY_SESSIONS and sticky_key in sticky_session_ids:
                                    debug_print(f"   Invalidating Sticky Session {current_session_id}...")
                                    del sticky_session_ids[sticky_key]
                                
                                # Longer delay for upstream rate limits (they need time to reset)
                                retry_delay = 3 + attempt * 2  # 3s, 5s, 7s, 9s
                                debug_print(f"🔄 Rotating token and waiting {retry_delay}s before retry (Attempt {attempt+2}/5)...")
                                await asyncio.sleep(retry_delay)
                                
                                current_headers = get_request_headers()
                                current_session_id = str(uuid7())
                                is_new_session = True
                                
                                if STICKY_SESSIONS:
                                    sticky_session_ids[sticky_key] = {
                                        "session_id": current_session_id,
                                        "headers": current_headers
                                    }
                                continue  # Retry loop with new token
                            
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
                                yield f"data: {fast_json_dumps(error_chunk)}\n\n"
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
                                yield f"data: {fast_json_dumps(error_chunk)}\n\n"
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
                
                # ============================================================
                # FAKE HISTORY MODE (Non-Streaming) - Send all chunks in ONE request!
                # ============================================================
                if FAKE_HISTORY_MODE and total_chunks > 1:
                    debug_print(f"📜 FAKE HISTORY MODE (Non-Stream): Bundling {total_chunks} chunks into single request")
                    
                    # Get headers and session
                    sticky_key = f"{api_key_str}:{model_public_name}"
                    if STICKY_SESSIONS and sticky_key in sticky_session_ids:
                        data = sticky_session_ids[sticky_key]
                        current_session_id = data["session_id"]
                        current_headers = data["headers"]
                        debug_print(f"📎 Reusing Sticky Session ID: {current_session_id}")
                    else:
                        current_headers = get_request_headers()
                        current_session_id = str(uuid7())
                        if STICKY_SESSIONS:
                            sticky_session_ids[sticky_key] = {
                                "session_id": current_session_id,
                                "headers": current_headers
                            }
                        debug_print(f"📎 Created New Session ID: {current_session_id}")
                    
                    # Small thinking delay
                    think_delay = random.uniform(0.5, 1.5)
                    debug_print(f"🤔 Thinking delay: {think_delay:.2f}s")
                    await asyncio.sleep(think_delay)
                    
                    # Build the fake history payload
                    payload = build_fake_history_payload(chunks, current_session_id)
                    
                    # Prepare headers
                    chunk_headers = {
                        "Cookie": current_headers.get("Cookie"),
                        "Content-Type": current_headers.get("Content-Type"),
                        "Referer": current_headers.get("Referer"),
                        "Origin": current_headers.get("Origin"),
                    }
                    chunk_headers = {k: v for k, v in chunk_headers.items() if v is not None}
                    
                    current_response_text = ""
                    finish_reason = "stop"
                    
                    # Retry loop
                    for attempt in range(5):
                        try:
                            debug_print(f"📡 Sending FAKE HISTORY POST request (attempt {attempt+1}/5)...")
                            response = await client.post(url, json=payload, headers=chunk_headers, timeout=180)
                            
                            if response.status_code in [429, 401, 403, 400]:
                                error_type = "Rate Limit" if response.status_code == 429 else "Auth/Bad Request Error"
                                debug_print(f"⚠️ {response.status_code} ({error_type})")
                                
                                if STICKY_SESSIONS and sticky_key in sticky_session_ids:
                                    del sticky_session_ids[sticky_key]
                                
                                if attempt < 4:
                                    debug_print(f"♻️ Rotating token and retrying (Attempt {attempt+2}/5)...")
                                    await asyncio.sleep(2 + attempt)
                                    current_headers = get_request_headers()
                                    current_session_id = str(uuid7())
                                    chunk_headers["Cookie"] = current_headers.get("Cookie")
                                    payload = build_fake_history_payload(chunks, current_session_id)
                                    if STICKY_SESSIONS:
                                        sticky_session_ids[sticky_key] = {
                                            "session_id": current_session_id,
                                            "headers": current_headers
                                        }
                                    continue
                            
                            response.raise_for_status()
                            
                            # Parse response
                            error_message = None
                            for line in response.text.splitlines():
                                line = line.strip()
                                if not line: continue
                                
                                if line.startswith("a0:"):
                                    try:
                                        text_chunk = json.loads(line[3:])
                                        current_response_text += text_chunk
                                    except: pass
                                elif line.startswith("a3:"):
                                    try:
                                        error_message = json.loads(line[3:])
                                        error_str = str(error_message).lower()
                                        
                                        rate_limit_keywords = [
                                            "resource exhausted", "rate limit", "429", "too many requests",
                                            "quota exceeded", "capacity", "overloaded", "try again later"
                                        ]
                                        is_rate_limit = any(kw in error_str for kw in rate_limit_keywords)
                                        
                                        if is_rate_limit and attempt < 4:
                                            print(f"  🔄 Detected upstream rate limit! Will rotate token and retry...")
                                            raise UpstreamRateLimitError(error_message)
                                    except UpstreamRateLimitError:
                                        raise
                                    except: 
                                        error_message = line[3:]
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
                            
                            # Success! Count tokens and return
                            try:
                                enc = tiktoken.get_encoding("cl100k_base")
                                prompt_tokens = len(enc.encode(prompt))
                                completion_tokens = len(enc.encode(current_response_text))
                                total_tokens_generated += completion_tokens
                                if model_public_name in model_usage_stats:
                                    model_usage_stats[model_public_name]["tokens"] += completion_tokens
                                add_activity(model_public_name, completion_tokens, "success")
                                debug_print(f"✅ FAKE HISTORY response complete | Tokens: {completion_tokens}")
                            except Exception:
                                prompt_tokens = len(prompt) // 4
                                completion_tokens = len(current_response_text) // 4
                                total_tokens_generated += completion_tokens
                                if model_public_name in model_usage_stats:
                                    model_usage_stats[model_public_name]["tokens"] += completion_tokens
                                add_activity(model_public_name, completion_tokens, "success")
                            
                            return {
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
                            
                        except UpstreamRateLimitError as e:
                            print(f"⚠️ Upstream rate limit: {e}")
                            if STICKY_SESSIONS and sticky_key in sticky_session_ids:
                                del sticky_session_ids[sticky_key]
                            retry_delay = 3 + attempt * 2
                            await asyncio.sleep(retry_delay)
                            current_headers = get_request_headers()
                            current_session_id = str(uuid7())
                            chunk_headers["Cookie"] = current_headers.get("Cookie")
                            payload = build_fake_history_payload(chunks, current_session_id)
                            if STICKY_SESSIONS:
                                sticky_session_ids[sticky_key] = {
                                    "session_id": current_session_id,
                                    "headers": current_headers
                                }
                            continue
                        except (HTTPError, Timeout, RequestsError, ConnectionError) as e:
                            print(f"❌ Request error: {e}")
                            if attempt < 4:
                                await asyncio.sleep(2)
                                current_headers = get_request_headers()
                                current_session_id = str(uuid7())
                                chunk_headers["Cookie"] = current_headers.get("Cookie")
                                payload = build_fake_history_payload(chunks, current_session_id)
                                continue
                            return {"error": {"message": f"Upstream error: {str(e)}", "type": "upstream_error", "code": 502}}
                    
                    # Exhausted retries
                    return {"error": {"message": "All retry attempts failed", "type": "upstream_error", "code": 502}}
                
                # ============================================================
                # LEGACY MODE (Non-Streaming) - Sequential chunk sending
                # ============================================================
                for i, chunk in enumerate(chunks):
                    # --- ROTATION LOGIC ---
                    is_new_session = False
                    if i % chunk_rotation_limit == 0:
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
                                        error_str = str(error_message).lower()
                                        
                                        # Check if this is a rate limit / resource exhausted error
                                        rate_limit_keywords = [
                                            "resource exhausted", "rate limit", "429", "too many requests",
                                            "quota exceeded", "capacity", "overloaded", "try again later"
                                        ]
                                        is_rate_limit = any(kw in error_str for kw in rate_limit_keywords)
                                        
                                        if is_rate_limit and attempt < 4:
                                            print(f"  🔄 Detected upstream rate limit in non-stream! Will rotate token and retry...")
                                            raise UpstreamRateLimitError(error_message)
                                    except UpstreamRateLimitError:
                                        raise  # Re-raise to be caught by outer retry loop
                                    except: 
                                        error_message = error_data
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
                            try:
                                enc = tiktoken.get_encoding("cl100k_base")
                                prompt_tokens = len(enc.encode(prompt))
                                completion_tokens = len(enc.encode(current_response_text))
                                total_tokens_generated += completion_tokens
                                # Update per-model token count
                                if model_public_name in model_usage_stats:
                                    model_usage_stats[model_public_name]["tokens"] += completion_tokens
                                # Add to activity log
                                add_activity(model_public_name, completion_tokens, "success")
                                debug_print(f"✅ Response complete | Prompt: {prompt_tokens} | Completion: {completion_tokens}")
                            except Exception:
                                # Fallback to character-based estimation
                                prompt_tokens = len(prompt) // 4
                                completion_tokens = len(current_response_text) // 4
                                total_tokens_generated += completion_tokens
                                if model_public_name in model_usage_stats:
                                    model_usage_stats[model_public_name]["tokens"] += completion_tokens
                                add_activity(model_public_name, completion_tokens, "success")
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
                        
                        except UpstreamRateLimitError as e:
                            # Upstream provider (Google, OpenAI, etc.) hit rate limit
                            print(f"⚠️ Upstream rate limit on Chunk {i+1}: {e}")
                            
                            if STICKY_SESSIONS and sticky_key in sticky_session_ids:
                                debug_print(f"   Invalidating Sticky Session {current_session_id}...")
                                del sticky_session_ids[sticky_key]
                            
                            # Longer delay for upstream rate limits
                            retry_delay = 3 + attempt * 2  # 3s, 5s, 7s, 9s
                            debug_print(f"🔄 Rotating token and waiting {retry_delay}s before retry (Attempt {attempt+2}/5)...")
                            await asyncio.sleep(retry_delay)
                            
                            current_headers = get_request_headers()
                            current_session_id = str(uuid7())
                            is_new_session = True
                            
                            if STICKY_SESSIONS:
                                sticky_session_ids[sticky_key] = {
                                    "session_id": current_session_id,
                                    "headers": current_headers
                                }
                            continue  # Retry loop with new token
                        
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