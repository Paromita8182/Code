import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
import urllib.parse
from urllib.parse import urlparse, urljoin
import re
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from dateutil import parser
import pytz


class URLFeatureExtractor:
    def __init__(self, api_keys: dict, url: str):

        # Validate API keys
        if not isinstance(api_keys, dict):
            raise TypeError("api_keys must be a dictionary.")

        # Ensure URL is a string and properly formatted
        if not isinstance(url, str) or not url.strip():
            raise ValueError("Invalid URL provided. Ensure it is a non-empty string.")

        self.url = url.strip()  # Remove extra spaces
        self.parsed_url = urllib.parse.urlparse(self.url)  # Parse URL once for reuse

        # Validate URL format
        if not self.parsed_url.scheme or not self.parsed_url.netloc:
            raise ValueError("Invalid URL format. Ensure it includes a scheme (http/https) and a domain.")

        self.domain = self.parsed_url.netloc.replace("www.", "")  # Extract clean domain
        self.api_keys = api_keys  # Store API keys for external services
        self.word_based_features = self.extract_words_from_url(self.parsed_url)  # Store extracted words for efficiency


    def url_length(self):
        return len(self.url)

    def hostname_length(self, parsed_url):
        return len(parsed_url.netloc)

    def count_dots(self):
        return self.url.count('.')

    def count_hyphens(self):
        return self.url.count('-')

    def count_question_marks(self):
        return self.url.count('?')

    def count_ampersands(self):
        return self.url.count('&')

    def count_equals(self):
        return self.url.count('=')

    def count_underscores(self):
        return self.url.count('_')

    def count_slashes(self):
        return self.url.count('/')

    def count_www(self):
        return self.url.count('www')

    def count_com(self):
        return self.url.count('com')

    def ratio_digits_url(self):
        length_url = self.url_length()
        if length_url == 0: 
            return 0
        no_of_digits_url = sum(1 for digit in self.url if digit.isnumeric())
        return no_of_digits_url / length_url

    def ratio_digits_hostname(self, parsed_url):
        length_hostname = self.hostname_length(parsed_url)
        if length_hostname == 0: 
            return 0
        no_of_digits_hostname = sum(1 for digit in parsed_url.netloc if digit.isnumeric())
        return no_of_digits_hostname / length_hostname

    def extract_words_from_url(self, parsed_url):
        netloc = parsed_url.netloc
        path = parsed_url.path
        netloc_words = re.split(r'[.\-_/=?@&%:]', netloc)
        path_words = re.split(r'[.\-_/=?@&%:]', path)
        full_words = list(filter(None, netloc_words + path_words))

        netloc_word_lengths = [len(word) for word in netloc_words if word]
        path_word_lengths = [len(word) for word in path_words if word]
        full_word_lengths = [len(word) for word in full_words]

        return {
            "full_words": full_words,
            "hostname_words": netloc_words,
            "path_words": path_words,
            "shortest_words_raw": min(full_word_lengths) if full_word_lengths else None,
            "longest_words_raw": max(full_word_lengths) if full_word_lengths else None,
            "shortest_word_host": min(netloc_word_lengths) if netloc_word_lengths else None,
            "longest_word_host": max(netloc_word_lengths) if netloc_word_lengths else None,
            "shortest_word_path": min(path_word_lengths) if path_word_lengths else None,
            "longest_word_path": max(path_word_lengths) if path_word_lengths else None
        }
    
    def count_repeated_chars(self, words_raw):
        repeat = {'2': 0, '3': 0, '4': 0, '5': 0}
        for word in words_raw:
            for length in range(2, 6):
                pattern = r"(.)\1{" + str(length - 1) + r"}"
                matches = re.findall(pattern, word)
                repeat[str(length)] += len(matches)
        return sum(repeat.values())
    

    def phish_hints(self, parsed_url):
        hints = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']
        return sum(parsed_url.path.lower().count(hint) for hint in hints)
    

    def count_hyperlinks(self, url):
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            hyperlinks = [a['href'] for a in soup.find_all('a', href=True)]
            return len(hyperlinks)
        except requests.RequestException:
            return None 
        

    def get_hyperlink_ratios(self, url):
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc

            internal_links = []
            external_links = []

            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(url, href)
                parsed_href = urlparse(full_url)

                if parsed_href.netloc == base_domain:
                    internal_links.append(full_url)
                else:
                    external_links.append(full_url)

            total_links = len(internal_links) + len(external_links)
            internal_ratio = len(internal_links) / total_links if total_links > 0 else 0
            external_ratio = len(external_links) / total_links if total_links > 0 else 0

            return {
                "internal_links": len(internal_links),
                "external_links": len(external_links),
                "ratio_intHyperlinks": internal_ratio,
                "ratio_extHyperlinks": external_ratio
            }

        except requests.RequestException:
            return {  # Avoid returning None
                "internal_links": 0,
                "external_links": 0,
                "ratio_intHyperlinks": 0,
                "ratio_extHyperlinks": 0
            }
        
    def count_external_css_files(self, url):
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc

            external_css_files = sum(1 for link_tag in soup.find_all('link', rel="stylesheet")
                                    if link_tag.get("href") and urlparse(urljoin(url, link_tag["href"])).netloc != base_domain)

            return external_css_files
        except requests.RequestException:
            return None
        
    def count_redirections(self, url):
        try:
            response = requests.get(url, allow_redirects=True, timeout=5)
            history = response.history
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc

            internal_redirects = sum(1 for redirect in history if urlparse(urljoin(url, redirect.headers.get("Location", ""))).netloc == base_domain)
            external_redirects = len(history) - internal_redirects

            total_redirects = internal_redirects + external_redirects
            return (internal_redirects / total_redirects, external_redirects / total_redirects) if total_redirects > 0 else (0, 0)

        except requests.RequestException as e:
            print(f"Error fetching URL: {e}")
            return None, None

    def get_hyperlink_error_ratios(self):
        try:
            response = requests.get(self.url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            base_domain = self.parsed_url.netloc
            internal_links, external_links = [], []
            for link in soup.find_all("a", href=True):
                full_url = urljoin(self.url, link["href"])
                (internal_links if urlparse(full_url).netloc == base_domain else external_links).append(full_url)

            def check_links(links):
                with ThreadPoolExecutor() as executor:
                    return sum(1 for future in as_completed([executor.submit(self.check_link_status, link) for link in links]) if future.result())

            return (check_links(internal_links) / len(internal_links) if internal_links else 0,
                    check_links(external_links) / len(external_links) if external_links else 0)
        except requests.RequestException:
            return None, None
        
    def check_link_status(self, url):
        try:
            return requests.head(url, allow_redirects=True, timeout=3).status_code >= 400
        except requests.RequestException:
            return True
        

    def get_internal_link_ratio(self):
        try:
            response = requests.get(self.url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            base_domain = self.parsed_url.netloc
            internal_links = sum(1 for link in soup.find_all("link", href=True)
                                 if urlparse(urljoin(self.url, link["href"])).netloc == base_domain)
            total_links = len(soup.find_all("link", href=True))
            return internal_links / total_links if total_links else 0
        except requests.RequestException:
            return None

    def get_internal_external_media_ratio(self):
        try:
            response = requests.get(self.url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            base_domain = self.parsed_url.netloc

            media_tags = ["img", "audio", "video", "source", "embed", "iframe"]
            internal_media, external_media = 0, 0

            for tag in media_tags:
                for media in soup.find_all(tag, src=True):
                    media_url = urlparse(urljoin(self.url, media["src"])).netloc
                    if media_url == base_domain:
                        internal_media += 1
                    else:
                        external_media += 1

            total_media = internal_media + external_media

            return (internal_media / total_media if total_media else 0,
                    external_media / total_media if total_media else 0)

        except requests.RequestException:
            return None, None
        

    def count_unsafe_anchors(self):
        try:
            response = requests.get(self.url, timeout=5)
            return sum(1 for a in BeautifulSoup(response.text, "html.parser").find_all("a", href=True)
                       if a["href"].lower().startswith(("#", "javascript:", "mailto:")))
        except requests.RequestException:
            return None
        
    def get_registration_length(self):
        base_url = 'https://www.whoisxmlapi.com/whoisserver/WhoisService'
        params = {
            'apiKey': self.api_keys.get('whois'),
            'domainName': self.domain,
            'outputFormat': 'JSON'
        }

        try:
            response = requests.get(base_url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()

            whois_record = data.get('WhoisRecord', {}).get('registryData', {})
            created_date_str = whois_record.get('createdDate')
            expires_date_str = whois_record.get('expiresDate')

            if not created_date_str or not expires_date_str:
                return None

            created_date = parser.parse(created_date_str).astimezone(pytz.UTC)
            expires_date = parser.parse(expires_date_str).astimezone(pytz.UTC)
            return (expires_date - created_date).days / 365

        except requests.RequestException as e:
            print(f"Error fetching WHOIS data: {e}")
            return None 
            
    def get_domain_age(self):
        base_url = 'https://www.whoisxmlapi.com/whoisserver/WhoisService'
        params = {
            'apiKey': self.api_keys.get('whois'),
            'domainName': self.domain,
            'outputFormat': 'JSON'
        }

        try:
            response = requests.get(base_url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()

            whois_record = data.get('WhoisRecord', {}).get('registryData', {})
            created_date_str = whois_record.get('createdDate')

            if not created_date_str:
                return None

            created_date = parser.parse(created_date_str).astimezone(pytz.UTC)
            current_date = datetime.now(pytz.UTC)
            return (current_date - created_date).days / 365

        except requests.RequestException as e:
            print(f"Error fetching WHOIS data: {e}")
            return None
        
    def get_ahrefs_traffic(self):
        base_url = "https://ahrefs2.p.rapidapi.com/traffic"
        headers = {
            "x-rapidapi-key": self.api_keys.get('ahrefs'),
            "x-rapidapi-host": "ahrefs2.p.rapidapi.com"
        }
        params = {"url": self.url, "mode": "subdomains"}

        try:
            response = requests.get(base_url, headers=headers, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()

            return data.get("trafficMonthlyAvg", None)

        except requests.RequestException as e:
            print(f"Error fetching Ahrefs traffic data: {e}")
            return None
            

    def get_page_rank(self):
        base_url = "https://openpagerank.com/api/v1.0/getPageRank"
        headers = {"API-OPR": self.api_keys.get('opr'), "Content-Type": "application/json"}
        params = {"domains[]": self.domain}

        try:
            response = requests.get(base_url, headers=headers, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()

            if data.get("response") and isinstance(data["response"], list) and len(data["response"]) > 0:
                return data["response"][0].get("page_rank_decimal", -1)  # Use -1 if not found

        except requests.RequestException as e:
            print(f"Error fetching PageRank data for {self.domain}: {e}")

        return None  # Return -1 for errors or missing data


    # def has_ip_address(self, url):
    #     ipv4_pattern = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
    #     ipv6_pattern = re.compile(r'([a-fA-F0-9]{1,4}:){7,7}[a-fA-F0-9]{1,4}|'
    #                               r'([a-fA-F0-9]{1,4}:){1,7}:|'
    #                               r'([a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|'
    #                               r'([a-fA-F0-9]{1,4}:){1,5}(:[a-fA-F0-9]{1,4}){1,2}|'
    #                               r'([a-fA-F0-9]{1,4}:){1,4}(:[a-fA-F0-9]{1,4}){1,3}|'
    #                               r'([a-fA-F0-9]{1,4}:){1,3}(:[a-fA-F0-9]{1,4}){1,4}|'
    #                               r'([a-fA-F0-9]{1,4}:){1,2}(:[a-fA-F0-9]{1,4}){1,5}|'
    #                               r'[a-fA-F0-9]{1,4}:((:[a-fA-F0-9]{1,4}){1,6})|'
    #                               r':((:[a-fA-F0-9]{1,4}){1,7}|:)|'
    #                               r'fe80:(:[a-fA-F0-9]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
    #                               r'::(ffff(:0{1,4}){0,1}:){0,1}'
    #                               r'((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3,3}'
    #                               r'(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])|'
    #                               r'([a-fA-F0-9]{1,4}:){1,4}:'
    #                               r'((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3,3}'
    #                               r'(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])')

    #     return 1 if ipv4_pattern.search(url) or ipv6_pattern.search(url) else 0


    # def has_ip_address(self):
    #     ipv4_pattern = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
    #     ipv6_pattern = re.compile(r'([a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}')

    def has_ip_address(self, url):
        ipv4_pattern = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
        ipv6_pattern = re.compile(r'([a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}')
        
        # Check if the URL matches either an IPv4 or IPv6 pattern
        return int(bool(ipv4_pattern.search(url) or ipv6_pattern.search(url)))
    
    
    def uses_https_protocol(self):
        return 1 if self.parsed_url.scheme == "https" else 0
    
    def prefix_suffix(self, url):
        return 1 if re.findall(r"https?://[^\-]+-[^\-]+/", url) else 0

    def check_external_favicon(self):
        try:
            response = requests.get(self.url, timeout=5)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")

            for link in soup.find_all("link", rel=["icon", "shortcut icon"]):
                href = link.get("href")
                if href and urlparse(urljoin(self.url, href)).netloc != self.parsed_url.netloc:
                    return 1

            return 0

        except requests.RequestException as e:
            print(f"Error fetching favicon data: {e}")
            return None
            
    def check_empty_title(self):
        try:
            response = requests.get(self.url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            title = soup.title.string.strip() if soup.title else ""

            return 1 if not title else 0  # Empty or missing title

        except requests.RequestException as e:
            print(f"Error fetching title for {self.url}: {e}")
            return None
        
    def check_domain_in_title(self):
        try:
            response = requests.get(self.url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            
            title = soup.title.string.strip().lower() if soup.title and soup.title.string else ""
            domain = self.parsed_url.netloc.replace("www.", "").lower()

            return 1 if domain in title else 0  # Check if domain appears in title

        except requests.RequestException as e:
            print(f"Error fetching page title: {e}")
            return None

    def check_domain_in_copyright(self):
        try:
            response = requests.get(self.url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            
            domain = self.parsed_url.netloc.replace("www.", "").lower()

            footer_elements = soup.find_all(["footer", "p", "div"])
            footer_texts = [element.get_text(strip=True).lower() for element in footer_elements if element.get_text(strip=True)]
            
            # Check if domain appears in any footer text
            return 1 if any(domain in text for text in footer_texts) else 0

        except requests.RequestException as e:
            print(f"Error fetching copyright data: {e}")
            return None


    def google_index(self):
        base_url = "https://www.googleapis.com/customsearch/v1"
        api_key = self.api_keys.get("google")
        cse_id = self.api_keys.get("cse_id")

        if not api_key or not cse_id:
            print("Error: Missing Google API credentials")
            return -1  # Error due to missing credentials

        params = {
            "key": api_key,
            "cx": cse_id,
            "q": f"site:{self.url}"
        }

        try:
            response = requests.get(base_url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()

            return 1 if "items" in data and data["items"] else 0  # Ensure "items" exists and is non-empty

        except requests.RequestException as e:
            print(f"Error fetching Google Index data for {self.url}: {e}")
            return None
            

    def extract_features(self):
        words_data = self.extract_words_from_url(self.parsed_url)
        redirections = self.count_redirections(self.url)
        hyperlink_errors = self.get_hyperlink_error_ratios()
        int_media_ratio, ext_media_ratio = self.get_internal_external_media_ratio()
        ratio_intRedirection, ratio_extRedirection = redirections if redirections else (None, None)
        ratio_intErrors, ratio_extErrors = hyperlink_errors if hyperlink_errors else (None, None)


        features_dict = {"length_url": self.url_length(),
            "length_hostname": self.hostname_length(self.parsed_url),
            "nb_dots": self.count_dots(),
            "nb_hyphens": self.count_hyphens(),
            "nb_qm": self.count_question_marks(),
            "nb_and": self.count_ampersands(),
            "nb_eq": self.count_equals(),
            "nb_underscore": self.count_underscores(),
            "nb_slash": self.count_slashes(),
            "nb_www": self.count_www(),
            "nb_com": self.count_com(),
            "ratio_digits_url": self.ratio_digits_url(),
            "ratio_digits_host": self.ratio_digits_hostname(self.parsed_url),
            "char_repeat": self.count_repeated_chars(words_data["full_words"]),
            "shortest_words_raw": words_data["shortest_words_raw"],
            "shortest_word_host": words_data["shortest_word_host"],
            "shortest_word_path": words_data["shortest_word_path"],
            "longest_words_raw": words_data["longest_words_raw"],
            "longest_word_host": words_data["longest_word_host"],
            "longest_word_path": words_data["longest_word_path"],
            "phish_hints": self.phish_hints(self.parsed_url),
            "nb_hyperlinks": self.count_hyperlinks(self.url),
            "ratio_intHyperlinks": self.get_hyperlink_ratios(self.url)["ratio_intHyperlinks"],
            "ratio_extHyperlinks": self.get_hyperlink_ratios(self.url)["ratio_extHyperlinks"],
            "nb_extCSS": self.count_external_css_files(self.url),
            "ratio_extRedirection": ratio_extRedirection,
            "ratio_extErrors": ratio_extErrors,
            "links_in_tags": self.get_internal_link_ratio(),
            "ratio_intMedia": int_media_ratio,
            "ratio_extMedia": ext_media_ratio,
            "safe_anchor": self.count_unsafe_anchors(),
            "domain_registration_length": self.get_registration_length(),
            "domain_age": self.get_domain_age(),  
            "web_traffic": 2000, #self.get_ahrefs_traffic(),
            "page_rank": self.get_page_rank(),
            "ip": self.has_ip_address(self.url),
            "https_token": self.uses_https_protocol(),
            "prefix_suffix": self.prefix_suffix(self.url),
            "external_favicon": self.check_external_favicon(),
            "empty_title": self.check_empty_title(),
            "domain_in_title": self.check_domain_in_title(),
            "domain_with_copyright": self.check_domain_in_copyright(),
            "google_index": self.google_index(),
          }
        
        features_df = pd.DataFrame([features_dict])
        return features_df


