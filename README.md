# secfeed
Stupid simple solution to keep track of various cyber security related sources including research blogs, CVEs, advisories, etc.

The script will query a list of websites and extract urls matching to specific regexs. If there are new sources (e.g. new CVE was released), a notification will be sent to Slack with the relevant link.

## Example
![Screen Shot 2022-12-16 at 12 57 18](https://user-images.githubusercontent.com/519424/208083709-cf006e4e-3a79-4681-b45f-ebb6efc4e0ac.png)

## How to run
- Edit `SLACK_URL` with your [Slack channel](https://api.slack.com/messaging/webhooks)
- Use `IS_TEST_MODE` to test if it works
- Use `SHOULD_REPORT` to send live notifications to the Slack channel
- Run using: `python3 secfeed.py`

## With Docker
- Copy `.env.sample` to `.env` in the root folder
- Edit `SLACK_URL` with your [Slack channel](https://api.slack.com/messaging/webhooks)
- Use `IS_TEST_MODE` to test if it works
- Use `SHOULD_REPORT` to send live notifications to the Slack channel
- Build docker image using: `docker build -t secfeed .`
- Run docker image using: `docker run --env-file ./.env secfeed`

Alternatively, you can also download the docker image directly from this repo under the **Packages** section.

## Why not RSS / Push notifications / netsec ?
Simply because many blogs/vendors are not supporting any form of push notifications or RSS. In addition not all CVE/Blog/Advisory are reaching main stream forums like Reddit.


## Add new source to track
- Add new item to the `SEC_FEEDS` dict:
```Python
"URL TO QUERY TO GET LINKS" : 
  (
    "BASE ADDRESS",
    r"EXTRACT WITH REGEX AND APPEND TO BASE ADDRESS",
    ["LIST", "OF", "KEYWORDS", "THAT AT LEAST", "ONE", "MUST", "EXISTS", "IN", "URL"]
  )
```

## Tracking list
- https://claroty.com/team82
- https://www.us-cert.gov/ics/advisories/
- https://cert.europa.eu/publications/security-advisories/
- https://www.tenable.com/security/research
- https://srcincite.io/blog/
- https://doar-e.github.io/blog/
- https://www.zerodayinitiative.com/advisories/published
- https://chemical-facility-security-news.blogspot.com/
- https://talosintelligence.com/vulnerability_reports
- https://cert.vde.com/en/advisories
- https://www.zeroscience.mk/en/vulnerabilities
- https://research.nccgroup.com/
- https://ssd-disclosure.com/advisories/
- https://awesec.com/advisories/ 
- https://www.nozominetworks.com/labs/labs-blogs/
- https://www.armis.com/research/ 
- https://research.checkpoint.com/
- https://blog.neodyme.io
- https://blog.viettelcybersecurity.com
- https://starlabs.sg/blog/
- https://www.seebug.org
