"""
Browser Automation and Evidence Collection Engine
Adds Selenium support for JavaScript-heavy targets
"""

import os
import base64
import json
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    logger.warning("Selenium not installed. Browser automation disabled.")

class BrowserEngine:
    """Browser automation with evidence collection"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.driver = None
        self.evidence_dir = self.config.get('evidence_dir', './evidence')
        self.screenshots = []
        self.har_data = []
        
        # Create evidence directory
        os.makedirs(self.evidence_dir, exist_ok=True)
        
        if SELENIUM_AVAILABLE:
            self._init_driver()
    
    def _init_driver(self):
        """Initialize headless Chrome driver"""
        if not SELENIUM_AVAILABLE:
            return
        
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')
        
        # Enable network logging for HAR
        options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
        
        try:
            self.driver = webdriver.Chrome(options=options)
            self.driver.set_page_load_timeout(30)
        except Exception as e:
            logger.error(f"Failed to initialize browser: {e}")
            self.driver = None
    
    def execute_js_payload(self, target: str, payload: str) -> Dict[str, Any]:
        """Execute JavaScript payload in browser context"""
        
        if not SELENIUM_AVAILABLE or not self.driver:
            return {'success': False, 'error': 'Browser automation not available'}
        
        try:
            # Navigate to target
            self.driver.get(target)
            time.sleep(2)  # Wait for page load
            
            # Take before screenshot
            before_screenshot = self._take_screenshot('before')
            
            # Execute payload
            result = self.driver.execute_script(payload)
            
            # Check for XSS indicators
            vulnerable = False
            indicators = []
            
            # Check for alert
            try:
                WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                vulnerable = True
                indicators.append(f'alert:{alert_text}')
            except TimeoutException:
                pass
            
            # Check DOM modifications
            dom_check = self.driver.execute_script("""
                return {
                    'scripts': document.scripts.length,
                    'iframes': document.getElementsByTagName('iframe').length,
                    'cookies': document.cookie
                }
            """)
            
            # Take after screenshot
            after_screenshot = self._take_screenshot('after')
            
            # Collect HAR data
            har = self._get_har_data()
            
            # Build evidence
            evidence = {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'payload': payload,
                'vulnerable': vulnerable,
                'indicators': indicators,
                'screenshots': {
                    'before': before_screenshot,
                    'after': after_screenshot
                },
                'dom_state': dom_check,
                'har': har,
                'javascript_result': str(result) if result else None
            }
            
            return {
                'success': vulnerable,
                'evidence': evidence,
                'confidence': 0.9 if vulnerable else 0.1
            }
            
        except Exception as e:
            logger.error(f"Browser execution failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _take_screenshot(self, name: str) -> str:
        """Take screenshot and return path"""
        if not self.driver:
            return None
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.evidence_dir}/screenshot_{name}_{timestamp}.png"
        
        try:
            self.driver.save_screenshot(filename)
            self.screenshots.append(filename)
            return filename
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            return None
    
    def _get_har_data(self) -> Dict:
        """Extract HAR data from browser logs"""
        if not self.driver:
            return {}
        
        try:
            logs = self.driver.get_log('performance')
            events = [json.loads(log['message'])['message'] for log in logs]
            
            har_data = {
                'requests': [],
                'responses': []
            }
            
            for event in events:
                if 'Network.requestWillBeSent' in event['method']:
                    har_data['requests'].append(event['params'])
                elif 'Network.responseReceived' in event['method']:
                    har_data['responses'].append(event['params'])
            
            return har_data
        except Exception as e:
            logger.error(f"HAR extraction failed: {e}")
            return {}
    
    def crawl_target(self, target: str) -> Dict[str, Any]:
        """Crawl target and build site map"""
        if not SELENIUM_AVAILABLE or not self.driver:
            return {'success': False, 'error': 'Browser automation not available'}
        
        try:
            self.driver.get(target)
            time.sleep(2)
            
            # Extract all links
            links = self.driver.execute_script("""
                return Array.from(document.querySelectorAll('a')).map(a => a.href);
            """)
            
            # Extract forms
            forms = self.driver.execute_script("""
                return Array.from(document.forms).map(form => ({
                    action: form.action,
                    method: form.method,
                    inputs: Array.from(form.elements).map(e => ({
                        name: e.name,
                        type: e.type,
                        value: e.value
                    }))
                }));
            """)
            
            # Extract JavaScript variables and endpoints
            js_analysis = self.driver.execute_script("""
                // Extract potential API endpoints from JavaScript
                const scripts = Array.from(document.scripts).map(s => s.innerHTML).join(' ');
                const apiPattern = /['"](\/api\/[^'"]*)['"]/g;
                const endpoints = [...new Set(scripts.match(apiPattern) || [])];
                
                // Extract global variables
                const globals = Object.keys(window).filter(k => 
                    !k.match(/^(webkit|moz|ms|chrome|CSS|HTML|SVG)/) &&
                    typeof window[k] !== 'function'
                ).slice(0, 50);
                
                return {
                    endpoints: endpoints,
                    globals: globals
                };
            """)
            
            return {
                'success': True,
                'sitemap': {
                    'links': links,
                    'forms': forms,
                    'javascript': js_analysis,
                    'screenshot': self._take_screenshot('sitemap')
                }
            }
            
        except Exception as e:
            logger.error(f"Crawling failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def cleanup(self):
        """Clean up browser resources"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
