import requests


def fetch(link):
    return requests.get(link, timeout=5).text
