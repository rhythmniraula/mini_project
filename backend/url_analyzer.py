import re
import urllib.parse
import logging
import requests
import tldextract
from urllib.parse import urlparse
import numpy as np
from bs4 import BeautifulSoup
from requests.exceptions import RequestException, Timeout

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class URLAnalyzer:
    def __init__(self):
        logger.info("Initializing URL Analyzer")
        self.phishing_keywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'password', 
            'banking', 'update', 'confirm', 'paypal', 'amazon', 'microsoft', 
            'apple', 'ebay', 'google', 'facebook', 'instagram', 'authorize',
            'wallet', 'security', 'verification', 'limited', 'unlock'
        ]
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
            '.work', '.date', '.faith', '.review', '.stream', '.win', '.racing'
        ]

    def extract_features(self, url):
        """
        Extract features from URL for phishing detection
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Dictionary of features extracted from the URL
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed_url = urlparse(url)
            extracted = tldextract.extract(url)
            domain = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
            
            # Basic URL features
            features = {
                'url': url,
                'domain': domain,
                'protocol': parsed_url.scheme,
                'path': parsed_url.path,
                'query': parsed_url.query,
                'url_length': len(url),
                'domain_length': len(domain),
                'num_dots': url.count('.'),
                'num_subdomains': len(extracted.subdomain.split('.')) if extracted.subdomain else 0,
                'has_ip_address': self._has_ip_address(url),
                'has_at_symbol': '@' in url,
                'has_double_slash_redirect': '//' in parsed_url.path,
                'has_hex_chars': bool(re.search(r'%[0-9a-fA-F]{2}', url)),
                'has_suspicious_tld': any(domain.endswith(tld) for tld in self.suspicious_tlds),
                'has_phishing_terms': any(keyword in url.lower() for keyword in self.phishing_keywords),
                'path_depth': len([p for p in parsed_url.path.split('/') if p]),
                'num_query_params': len(parsed_url.query.split('&')) if parsed_url.query else 0
            }
            
            # Add anchor analysis
            features['has_suspicious_anchor'] = '#' in url and not parsed_url.fragment.startswith(('top', 'footer'))
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting URL features: {str(e)}")
            return None

    def fetch_website_content(self, url, timeout=5):
        """
        Safely fetch content from a website with timeout
        
        Args:
            url (str): URL to fetch
            timeout (int): Timeout in seconds
            
        Returns:
            tuple: (response content, status code) or (None, None) on error
        """
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
            return response.content, response.status_code
        except Timeout:
            logger.warning(f"Timeout when fetching {url}")
            return None, 'timeout'
        except RequestException as e:
            logger.warning(f"Error fetching URL {url}: {str(e)}")
            return None, 'error'
        except Exception as e:
            logger.error(f"Unexpected error fetching URL {url}: {str(e)}")
            return None, 'error'

    def analyze_website_content(self, url):
        """
        Analyze website content for phishing indicators
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Analysis results including content-based features
        """
        content, status = self.fetch_website_content(url)
        if not content:
            return {
                'fetch_status': status,
                'content_available': False
            }
            
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract features from website content
            content_features = {
                'fetch_status': status,
                'content_available': True,
                'has_password_field': bool(soup.find('input', {'type': 'password'})),
                'has_login_form': bool(soup.find('form')) and any(keyword in str(soup).lower() for keyword in ['login', 'signin', 'log in', 'sign in']),
                'has_external_css': len(soup.find_all('link', {'rel': 'stylesheet'})) > 0,
                'num_scripts': len(soup.find_all('script')),
                'num_iframes': len(soup.find_all('iframe')),
                'num_forms': len(soup.find_all('form')),
                'title': soup.title.text if soup.title else '',
                'favicon_domain_match': self._check_favicon_domain_match(soup, url),
                'external_links_ratio': self._calculate_external_links_ratio(soup, url)
            }
            
            return content_features
            
        except Exception as e:
            logger.error(f"Error analyzing website content: {str(e)}")
            return {
                'fetch_status': 'error',
                'content_available': False,
                'error': str(e)
            }

    def is_phishing(self, url, check_content=False):
        """
        Combined analysis to determine if a URL is likely a phishing site
        
        Args:
            url (str): URL to analyze
            check_content (bool): Whether to also check website content
            
        Returns:
            dict: Analysis results with phishing score and explanation
        """
        # Extract URL features
        features = self.extract_features(url)
        if not features:
            return {
                'is_phishing': None,
                'score': None,
                'reason': "Failed to extract URL features"
            }
            
        # Calculate initial score based on URL features
        score = 0
        reasons = []
        
        # Check URL length (phishing URLs often very long)
        if features['url_length'] > 75:
            score += 0.1
            reasons.append("Unusually long URL")
            
        # Check for IP address in domain
        if features['has_ip_address']:
            score += 0.3
            reasons.append("IP address used instead of domain name")
            
        # Check for @ symbol in URL
        if features['has_at_symbol']:
            score += 0.3
            reasons.append("URL contains @ symbol, which can be used for deception")
            
        # Check for double slash redirect
        if features['has_double_slash_redirect']:
            score += 0.2
            reasons.append("URL contains suspicious redirect with double slashes")
            
        # Check for hex characters
        if features['has_hex_chars']:
            score += 0.1
            reasons.append("URL contains suspicious hexadecimal characters")
            
        # Check for suspicious TLD
        if features['has_suspicious_tld']:
            score += 0.2
            reasons.append(f"Domain uses suspicious TLD ({features['domain']})")
            
        # Check for phishing terms
        if features['has_phishing_terms']:
            score += 0.2
            reasons.append("URL contains terms commonly used in phishing")
            
        # Check excessive subdomains
        if features['num_subdomains'] >= 3:
            score += 0.1
            reasons.append(f"Excessive number of subdomains ({features['num_subdomains']})")
            
        # Check for suspicious anchor
        if features['has_suspicious_anchor']:
            score += 0.1
            reasons.append("Contains suspicious anchor tag usage")
            
        # If requested, also check website content
        content_analysis = None
        if check_content and score < 0.7:  # Don't waste time on already suspicious URLs
            content_analysis = self.analyze_website_content(url)
            
            if content_analysis.get('content_available'):
                # Check for password fields
                if content_analysis.get('has_password_field'):
                    score += 0.1
                    reasons.append("Page contains password field")
                    
                # Check for login forms
                if content_analysis.get('has_login_form'):
                    score += 0.1
                    reasons.append("Page contains login form")
                    
                # Check for low external CSS (phishing sites often have minimal styling)
                if not content_analysis.get('has_external_css'):
                    score += 0.05
                    reasons.append("Page lacks external CSS stylesheets")
                    
                # Check external links ratio
                if content_analysis.get('external_links_ratio', 0) < 0.2:
                    score += 0.05
                    reasons.append("Few external domain links (isolation tactic)")
                    
                # Check favicon domain match
                if not content_analysis.get('favicon_domain_match'):
                    score += 0.1
                    reasons.append("Favicon doesn't match domain (possible impersonation)")
        
        # Determine phishing status
        is_phishing = None
        risk_level = None
        
        if score >= 0.7:
            is_phishing = True
            risk_level = "High Risk"
        elif score >= 0.4:
            is_phishing = True
            risk_level = "Medium Risk"
        elif score >= 0.2:
            is_phishing = False
            risk_level = "Low Risk"
        else:
            is_phishing = False
            risk_level = "Minimal Risk"
            
        # Return results
        result = {
            'is_phishing': is_phishing,
            'risk_level': risk_level,
            'score': round(score, 2),
            'reasons': reasons if reasons else ["No suspicious elements detected"],
            'url_features': features
        }
        
        if content_analysis:
            result['content_analysis'] = content_analysis
            
        return result

    def _has_ip_address(self, url):
        """Check if the URL contains an IP address instead of a domain name"""
        # IPv4 pattern
        ipv4_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
        # IPv6 pattern (simplified)
        ipv6_pattern = r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
        
        return bool(re.search(ipv4_pattern, url) or re.search(ipv6_pattern, url))

    def _check_favicon_domain_match(self, soup, url):
        """Check if favicon domain matches the main domain"""
        try:
            favicon = soup.find('link', rel=lambda r: r and ('icon' in r.lower()))
            if not favicon or not favicon.get('href'):
                return True  # No favicon to check, assume match
                
            favicon_url = favicon['href']
            if favicon_url.startswith('/'):
                return True  # Local favicon, matches domain
                
            if favicon_url.startswith('http'):
                favicon_domain = tldextract.extract(favicon_url).domain
                url_domain = tldextract.extract(url).domain
                return favicon_domain == url_domain
                
            return True  # Default is no mismatch
        except Exception:
            return True  # On error, assume match

    def _calculate_external_links_ratio(self, soup, url):
        """Calculate ratio of external links to total links"""
        try:
            base_domain = tldextract.extract(url).domain
            links = soup.find_all('a', href=True)
            
            if not links:
                return 0.0
                
            external_links = 0
            for link in links:
                href = link['href']
                if href.startswith(('http://', 'https://')):
                    link_domain = tldextract.extract(href).domain
                    if link_domain != base_domain:
                        external_links += 1
                        
            return external_links / len(links)
        except Exception:
            return 0.0  # On error, return zero ratio 