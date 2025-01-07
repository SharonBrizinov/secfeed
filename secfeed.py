# secfeed by Sharon Brizinov 2025
import random
import logging
import requests
import time
import pickle
import re
import sys
import json
import urllib3

urllib3.disable_warnings()


DB_PATH = "secfeed.db"
LIST_PARSED_DATA = []

IS_TEST_MODE = True
SHOULD_REPORT = False


# replace this with real slack/telegram IDs
SLACK_URL = None            #"https://hooks.slack.com/services/XXXXXXX/YYYYYYYYYYY/ZZZZZZZZZZ" 
TELEGRAM_BOT = None         # "1111111111:AAAAAAAAAAAAAAAAAA-XXXXXXXXXXXXX"
TELEGRAM_BOT_CHAT = None    # "123456789"
SIGNAL_URL = None           # "http://127.0.0.1:8080/v2/send"
SIGNAL_SENDER = None        # "+4412345"
SIGNAL_RECIEPIENTS = None   # [ "+4412345" ]
DISCORD_URL = None          #"https://discord.com/api/webhooks/YYYYYYYYYYY/XXXXXXXXXXXXXXXXX"

REQUEST_TIMEOUT = 5
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
SLEEP_TIME = 60 * 60 * 2 # 2 hours -+ 10-5000 seconds

SEC_FEEDS = {
         # Example:
         # "URL TO QUERY TO GET LINKS" : 
         #    ("BASE ADDRESS",
         #    r"EXTRACT WITH REGEX AND APPEND TO BASE ADDRESS",
         #    ["LIST", "OF", "KEYWORDS", "THAT AT LEAST", ONE", "MUST", "EXISTS", "IN", "URL"]),

        # https://claroty.com/team82/research/
       	"https://claroty.com/team82/research/":
            ("https://claroty.com/team82/research/",
            r"href=\"/team82/research/([^\"]+)\"",
            None,
            USER_AGENT),

        # https://www.cisa.gov/news-events/cybersecurity-advisories
        "https://www.cisa.gov/cybersecurity-advisories/all.xml" : 
            ("",
            r"<link>([^\"]+?)</link>",
            None,
            None),

       # <a href="/publications/security-advisories/2024-118/" class="publications--list--item--link">
       "https://cert.europa.eu/publications/security-advisories/" :
           ("https://cert.europa.eu/publications/security-advisories/",
           r"/publications/security-advisories/(\d+\-\d+/)", 
           None,
           USER_AGENT),

        # https://www.tenable.com/security/research/tra-2020-34
        "https://www.tenable.com/security/research" : 
             ("https://www.tenable.com/security/research/tra-",
             r"/security/research/tra-(\d+\-\d+)",
             None,
             USER_AGENT), 

        # https://srcincite.io/blog/
        "https://srcincite.io/blog/":
            ("https://srcincite.io/blog/",
            r"<a class=\"post-link\" href=\"/blog/(\d+/\d+/\d+/[^\"]+)\">",
            None,
            USER_AGENT),

        # https://doar-e.github.io/index.html
        "https://doar-e.github.io/index.html":
            ("https://doar-e.github.io/blog/",
            r"\"\./blog/(\d+/\d+/\d+/[^\"]+)\">",
            None,
            USER_AGENT),

        # https://www.zerodayinitiative.com/advisories/ZDI-20-683/
        "https://www.zerodayinitiative.com/advisories/published" :
             ("https://www.zerodayinitiative.com/advisories/ZDI-",
             r"ZDI-(\d+\-\d+)",
             None,
             USER_AGENT), 

        # https://chemical-facility-security-news.blogspot.com/2020/05/public-ics-disclosures-week-of-5-23-20.html, https://chemical-facility-security-news.blogspot.com/2022/12/review-3-advisories-published-12-8-22.html
        "https://chemical-facility-security-news.blogspot.com/" : 
             ("https://chemical-facility-security-news.blogspot.com/", 
             r"\.blogspot\.com/(\d+/\d+/[\w+\d+\-]+\.html)", 
             ["disclosure", "advisories", "advisory"],
             USER_AGENT),
         
        "https://talosintelligence.com/vulnerability_reports" : 
            ("https://talosintelligence.com/vulnerability_reports/TALOS-", 
            r"/vulnerability_reports/TALOS-(\d+\-\d+)", 
            None,
            USER_AGENT), # https://talosintelligence.com/vulnerability_reports/TALOS-2020-1056
         
        "https://cert.vde.com/en/advisories" : 
            ("https://cert.vde.com/en/advisories/", 
            r"advisories/([vV][dD][eE]\-\d+\-\d+)", 
            None,
            USER_AGENT), # https://cert.vde.com/en/advisories/VDE-2021-045/
         
         "https://www.zeroscience.mk/en/vulnerabilities" : 
            ("https://www.zeroscience.mk/en/vulnerabilities/", 
            r"(ZSL-20\d+-\d+.php)", 
            None,
            USER_AGENT),

        # https://ssd-disclosure.com/apple-safari-javascriptcore-inspector-type-confusion/
        "https://ssd-disclosure.com/advisories/" : 
            ("https://ssd-disclosure.com/", 
            r"<a href=\"https://ssd-disclosure\.com/([^\"]+)\" \>", 
            None,
            USER_AGENT), 
         
        "https://awesec.com/advisories.html" : 
            ("https://awesec.com/advisories/", 
            r"advisories\/(AWE-\d+-\d+\.html)\">", 
            None,
            USER_AGENT),

        # https://www.nozominetworks.com/blog/ge-healthcare-vivid-ultrasound-vulnerabilities
        "https://www.nozominetworks.com/labs": 
            ("https://www.nozominetworks.com/blog/", 
            r"<a href\=\"/blog/([^\"]+)\"", 
            None,
            USER_AGENT), 

        # https://www.armis.com/research/tlstorm/
        "https://www.armis.com/armis-labs/": 
            ("https://www.armis.com/research/", 
            r"armis\.com\/research\/([^\"]+)\"", 
            None,
            USER_AGENT), 

        # https://research.checkpoint.com/?p=26395
        "https://research.checkpoint.com/feed/" : 
            ("https://research.checkpoint.com/?p=", 
            r"research.checkpoint.com\/\?p=(\d+)<\/guid>", 
            None,
            USER_AGENT),

        # https://blog.neodyme.io/posts/secure-randomness-part-2/
        "https://neodyme.io/en/blog/":
            ("https://neodyme.io/",
            r"<a href=\"([^\"]+)\" class",
            None,
            USER_AGENT),
 
        # https://starlabs.sg/blog/2022/12-the-last-breath-of-our-netgear-rax30-bugs-a-tragic-tale-before-pwn2own-toronto-2022/
        "https://starlabs.sg/blog/":
            ("https://starlabs.sg/blog/",
            r"\"https://starlabs.sg/blog/(\d+/[^\"]+)\"",
            None,
            USER_AGENT),

        # https://www.seebug.org/vuldb/ssvid-99599
        "https://www.seebug.org/rss/new/":
            ("",
            r"(http://www.seebug.org/vuldb/ssvid-\d+)",
            None,
            USER_AGENT),            

        # https://www.forescout.com/research-labs-overview/
       	"https://www.forescout.com/research-labs-overview/":
            ("https://www.forescout.com/blog/",
            r"href=\"/blog/(.*?)\"",
            None,
            USER_AGENT),

        # https://www.interruptlabs.co.uk/labs
        "https://www.interruptlabs.co.uk/labs":
            ("https://www.interruptlabs.co.uk/articles/",
            r"href=\"/articles/(.*?)\"",
            None,
            USER_AGENT),

        # https://www.flashback.sh/blog
        "https://www.flashback.sh/blog":
            ("https://www.flashback.sh/blog/",
            r"href=\"/blog/(.*?)\"",
            None,
            USER_AGENT),

        # https://xl-sec.github.io/AppSecEzine/latest.rss
        "https://xl-sec.github.io/AppSecEzine/latest.rss":
            ("",
            r"<link>(.*)</link>",
            None,
            USER_AGENT),

        # https://icsstrive.com/
        "https://icsstrive.com":
            ("https://icsstrive.com/incident/",
            r"href=\"https://icsstrive\.com/incident/(.*?)\">",
            None,
            USER_AGENT),

        # https://wordfence.com/
        "https://www.wordfence.com/threat-intel":
            ("https://www.wordfence.com/threat-intel/vulnerabilities/",
            r"href=\"https://www\.wordfence\.com/threat-intel/vulnerabilities/(.*?)\">",
            ["bypass", "unauth","preauth"],
            USER_AGENT),

        "https://www.zerodayinitiative.com/blog/":
            ("https://www.zerodayinitiative.com/blog/",
            r"href=\"/blog/([^\"]+)\"",
            None,
            USER_AGENT),

        "https://www.wiz.io/blog/tag/research":
            ("https://www.wiz.io/blog/",
            r"href=\"/blog/([^\"]+)\"",
            None,
            USER_AGENT),

        "https://labs.watchtowr.com/":
            ("https://labs.watchtowr.com/",
            r"gh-card-link\" href=\"/([^\"]+)\"",
            None,
            USER_AGENT),

        "https://blog.qualys.com/comments/feed":
            ("",
            r"<link>(.*?)</link>",
            None,
            USER_AGENT),
            
         "https://cyberdanube.com/security-research/":
            ("",
            r'https://cyberdanube\.com/security-research/[a-zA-Z0-9\-/]+/',
            None,
            USER_AGENT),
}

def setup_logger():
    logging.basicConfig(filename="secfeed.log", filemode="w", level=logging.DEBUG)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)


def notify_slack(url):
    if SHOULD_REPORT:
        if SLACK_URL:
            data = {"text" : url, "unfurl_links": True, "unfurl_media": True}
            resp = requests.post(SLACK_URL, data=json.dumps(data))
            logging.debug("Slack responded: '{}'".format(resp.text))

def notify_telegram(url):
    if SHOULD_REPORT:
        if TELEGRAM_BOT and TELEGRAM_BOT_CHAT:
            telegram_url_full = f"https://api.telegram.org/bot{TELEGRAM_BOT}/sendMessage"
            resp = requests.post(telegram_url_full, data={"chat_id": TELEGRAM_BOT_CHAT, "text": url})
            logging.debug("Telegram responded: '{}'".format(resp.text))

def notify_signal(url):
    if SHOULD_REPORT:
        if SIGNAL_URL and SIGNAL_SENDER and SIGNAL_RECIEPIENTS:
            data = {"message": url, "number": SIGNAL_SENDER, "recipients": SIGNAL_RECIEPIENTS }
            resp = requests.post(SIGNAL_URL, data=json.dumps(data))
            logging.debug("Signal responded: '{}'".format(resp.text))

def notify_discord(url):
    if SHOULD_REPORT:
        if DISCORD_URL:
            data = {"content": url}
            header = {'Content-Type': 'application/json'}
            resp = requests.post(DISCORD_URL, headers=header,data=json.dumps(data))
            logging.debug("Discord responded: '{}'".format(resp.text))


setup_logger()


if not IS_TEST_MODE:
    try:
        # First load from database everything we have
        logging.info("Loading data from: {}".format(DB_PATH))
        with open(DB_PATH, "rb") as f:
            LIST_PARSED_DATA = pickle.load(f)
        logging.info("Loaded {} entries from DB".format(len(LIST_PARSED_DATA)))
    except Exception as e:
        pass

while True:
    logging.info("Getting data")

    for sec_feed in SEC_FEEDS:
        if IS_TEST_MODE:
            print("--> {}".format(sec_feed))

        # Prepare
        url_feed = sec_feed
        # one keyword must be present
        base_url, regex_str, keywords, ua = SEC_FEEDS[url_feed]
        keywords = keywords or []

        HEADERS = None
        if ua:
            HEADERS = {"User-Agent": ua}

        # Get data
        try:
            data = requests.get(sec_feed, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=False)
        except Exception as e:
            continue
        # Extract
        extracted_datas = re.findall(regex_str, data.text)
        for extracted_data in extracted_datas:
            extracted_data = extracted_data or ""
            if not keywords or any([keyword.lower() in extracted_data.lower() for keyword in keywords]):
                full_url = base_url + extracted_data
                if IS_TEST_MODE:
                    print("  [-] {}".format(full_url))
                else:
                    if full_url not in LIST_PARSED_DATA:
                        logging.info("Saving new url, and notifying slack: '{}'".format(full_url))
                        LIST_PARSED_DATA.append(full_url)
                        notify_slack(full_url)
                        notify_telegram(full_url)
                        notify_signal(full_url)
                        notify_discord(full_url)
    if not IS_TEST_MODE:
        logging.info("Saving everything back to DB: {}".format(DB_PATH))
        with open(DB_PATH, "wb") as f:
            pickle.dump(LIST_PARSED_DATA, f)

        rand_time = random.randint(10, 5000)
        logging.info("Going to sleep {:.2f} hours".format((rand_time+SLEEP_TIME) / 3600.0))
        time.sleep(SLEEP_TIME + rand_time)
    else:
        break
