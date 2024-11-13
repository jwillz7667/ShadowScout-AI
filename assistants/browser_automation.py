from playwright.async_api import async_playwright
from typing import Dict, Any, List
import asyncio
import logging
from urllib.parse import urljoin

class BrowserAutomation:
    def __init__(self):
        self.browser = None
        self.context = None
        self.page = None
        self.logger = logging.getLogger("BrowserAutomation")

    async def initialize(self, stealth_mode: bool = False):
        """Initialize browser with stealth options if needed"""
        playwright = await async_playwright().start()
        
        browser_args = ['--no-sandbox']
        if stealth_mode:
            browser_args.extend([
                '--disable-blink-features=AutomationControlled',
                '--disable-features=IsolateOrigins,site-per-process',
            ])
        
        self.browser = await playwright.chromium.launch(
            headless=True,
            args=browser_args
        )
        
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        
        if stealth_mode:
            await self.context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            """)
        
        self.page = await self.context.new_page()
        return self

    async def scan_page(self, url: str) -> Dict[str, Any]:
        """Perform detailed page scan"""
        try:
            await self.page.goto(url, wait_until='networkidle')
            
            # Collect basic page info
            title = await self.page.title()
            content = await self.page.content()
            
            # Find forms and inputs
            forms = await self.page.query_selector_all('form')
            form_data = []
            for form in forms:
                inputs = await form.query_selector_all('input')
                form_data.append({
                    'action': await form.get_attribute('action'),
                    'method': await form.get_attribute('method'),
                    'inputs': [await self._get_input_info(input_) for input_ in inputs]
                })
            
            # Check for common security headers
            security_headers = await self._check_security_headers()
            
            # Find potential XSS injection points
            xss_points = await self._find_xss_points(url)
            
            # Collect JavaScript files
            scripts = await self._collect_scripts()
            
            return {
                'title': title,
                'url': url,
                'forms': form_data,
                'security_headers': security_headers,
                'potential_xss_points': xss_points,
                'scripts': scripts,
                'cookies': await self._get_cookies()
            }
            
        except Exception as e:
            self.logger.error(f"Error scanning page {url}: {str(e)}")
            return {'error': str(e)}

    async def _get_input_info(self, input_element) -> Dict[str, str]:
        """Get detailed information about an input element"""
        props = ['name', 'type', 'id', 'class', 'value']
        info = {}
        for prop in props:
            info[prop] = await input_element.get_attribute(prop)
        return info

    async def _check_security_headers(self) -> Dict[str, str]:
        """Check security-related headers"""
        response = await self.page.request.all()[0].response()
        headers = response.headers
        security_headers = {
            'X-Frame-Options': headers.get('x-frame-options', 'Not Set'),
            'X-XSS-Protection': headers.get('x-xss-protection', 'Not Set'),
            'Content-Security-Policy': headers.get('content-security-policy', 'Not Set'),
            'X-Content-Type-Options': headers.get('x-content-type-options', 'Not Set'),
            'Strict-Transport-Security': headers.get('strict-transport-security', 'Not Set')
        }
        return security_headers

    async def _find_xss_points(self, url: str) -> List[Dict[str, Any]]:
        """Find potential XSS injection points"""
        xss_points = []
        
        # Check URL parameters
        params = await self.page.evaluate("""() => {
            return window.location.search;
        }""")
        if params:
            xss_points.append({
                'type': 'URL Parameter',
                'location': 'query string',
                'value': params
            })
        
        # Check input fields
        inputs = await self.page.query_selector_all('input[type="text"], input[type="search"], textarea')
        for input_ in inputs:
            xss_points.append({
                'type': 'Input Field',
                'id': await input_.get_attribute('id'),
                'name': await input_.get_attribute('name')
            })
        
        # Check for reflected content
        test_strings = ["'';!--\"<XSS>=&{()}", "<script>alert(1)</script>"]
        for test_string in test_strings:
            # Check URL reflection
            test_url = f"{url}?test={test_string}"
            await self.page.goto(test_url, wait_until='networkidle')
            content = await self.page.content()
            if test_string in content:
                xss_points.append({
                    'type': 'Reflected Content',
                    'location': 'URL Parameter',
                    'value': test_string
                })
        
        return xss_points

    async def _collect_scripts(self) -> List[str]:
        """Collect all JavaScript file URLs"""
        scripts = await self.page.query_selector_all('script[src]')
        script_urls = []
        for script in scripts:
            src = await script.get_attribute('src')
            if src:
                script_urls.append(urljoin(self.page.url, src))
        return script_urls

    async def _get_cookies(self) -> List[Dict[str, Any]]:
        """Get all cookies"""
        return await self.context.cookies()

    async def close(self):
        """Clean up resources"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close() 