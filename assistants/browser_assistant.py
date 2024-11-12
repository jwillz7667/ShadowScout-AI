import asyncio
from playwright.async_api import async_playwright

class BrowserAssistant:
    def __init__(self):
        self.browser = None
        self.context = None
        
    async def browse_page(self, url: str) -> str:
        """Browse and extract page content."""
        try:
            if not self.browser:
                playwright = await async_playwright().start()
                self.browser = await playwright.chromium.launch(headless=True)
                self.context = await self.browser.new_context()
            
            page = await self.context.new_page()
            await page.goto(url)
            content = await page.content()
            await page.close()
            return content
        except Exception as e:
            return f"Error browsing page: {str(e)}"

    async def check_robots(self, url: str) -> str:
        """Check robots.txt and sitemap."""
        try:
            domain = url.split("://")[1].split("/")[0]
            robots_url = f"https://{domain}/robots.txt"
            sitemap_content = []
            
            if not self.browser:
                playwright = await async_playwright().start()
                self.browser = await playwright.chromium.launch(headless=True)
                self.context = await self.browser.new_context()
            
            page = await self.context.new_page()
            await page.goto(robots_url)
            robots_content = await page.content()
            
            # Check for sitemap
            if "Sitemap:" in robots_content:
                sitemap_url = robots_content.split("Sitemap:")[1].split("\n")[0].strip()
                await page.goto(sitemap_url)
                sitemap_content = await page.content()
            
            await page.close()
            return f"Robots.txt:\n{robots_content}\n\nSitemap:\n{''.join(sitemap_content)}"
        except Exception as e:
            return f"Error checking robots.txt: {str(e)}"

    async def close_browser(self):
        """Close browser and cleanup."""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()