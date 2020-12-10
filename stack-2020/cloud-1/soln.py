wordlist = [
    "wireless",
    "digital",
    "parking",
    "data",
    "information",
    "architecture",
    "wifi",
    "smartcity",
    "computer",
    "efficiency",
    "technology",
    "payment",
    "ai",
    "fintech",
    "analytics",
    "knowledge",
    "applications",
    "mobile",
    "internet",
    "systems",
    "cybersecurity",
    "communication",
    "iot",
    "intelligent",
    "innovation",
    "crazy",
    "change",
    "world",
    "people",
    "think",
]

import itertools, requests
import asyncio


def ping(pair):
    url = "http://{}-{}-s4fet3ch.s3.amazonaws.com/".format(*pair)
    resp = requests.get(url)
    if resp.status_code != 404:
        print(pair)
        print(url)
        return


buzzwords = list(itertools.permutations(wordlist, 2))
loop = asyncio.get_event_loop()
for pair in buzzwords:
    loop.run_in_executor(None, ping, pair)
