import asyncio
import base64
import os
import re
from playwright.sync_api import sync_playwright, TimeoutError, Page
from playwright.async_api import async_playwright, TimeoutError
#from markdownify import markdownify as md
#from pdfminer.high_level import extract_text
from bs4 import BeautifulSoup

def parse_html(html_content):
    soup = BeautifulSoup(html_content, features="html.parser")
    elements = soup.select('p, table, pre, ul, ol')  # Select the specified tags

    if not elements:
        print('Webpage does not have any parseable element')

    # Extract and combine the text from the selected elements
    text = ' '.join(element.get_text(strip=True) for element in elements)
    text = re.sub(r' {2}|\r\n|\n|\r', ' ', text)
    return text

class Browser:
    def __init__(self):
        self.playwright = None
        self.browser = None
        self.page = None

    async def start(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        self.page = await self.browser.new_page()
        return self

    async def go_to(self, url):
        try:
            await self.page.goto(url, timeout=20000,wait_until='networkidle')
        except TimeoutError as e:
            print(f"TimeoutError: {e} when trying to navigate to {url}")
            return False
        return True

    async def screenshot(self, project_name,screenshot_dir="./"):
        screenshots_save_path = screenshot_dir

        page_metadata = await self.page.evaluate("() => { return { url: document.location.href, title: document.title } }")
        page_url = page_metadata['url']
        random_filename = os.urandom(20).hex()
        filename_to_save = f"{random_filename}.png"
        path_to_save = os.path.join(screenshots_save_path, filename_to_save)

        await self.page.emulate_media(media="screen")
        await self.page.screenshot(path=path_to_save)
        screenshot = await self.page.screenshot()
        screenshot_bytes = base64.b64encode(screenshot).decode()
        # self.close()
        return path_to_save, screenshot_bytes

    def get_html(self):
        return self.page.content()

    #def get_markdown(self):
    #    return md(self.page.content())

    def get_pdf(self,pdf_dir="./"):
        pdfs_save_path = pdf_dir

        page_metadata = self.page.evaluate("() => { return { url: document.location.href, title: document.title } }")
        filename_to_save = f"{page_metadata['title']}.pdf"
        save_path = os.path.join(pdfs_save_path, filename_to_save)
        self.page.pdf(path=save_path)
        return save_path

    #def pdf_to_text(self, pdf_path):
    #    return extract_text(pdf_path).strip()

    #def get_content(self):
    #    pdf_path = self.get_pdf()
    #    return self.pdf_to_text(pdf_path)

    async def extract_text(self):
        html = await self.page.content()
        return  parse_html(html)

    async def close(self):
        await self.page.close()
        await self.browser.close()
