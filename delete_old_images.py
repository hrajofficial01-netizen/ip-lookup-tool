import requests
import os
from requests.auth import HTTPBasicAuth

DOCKER_USERNAME = os.getenv("DOCKER_USERNAME")
DOCKER_REPO = os.getenv("DOCKER_REPO")
DOCKER_PASSWORD = os.getenv("DOCKER_PASSWORD")  # Docker Hub Personal Access Token

API_BASE = "https://hub.docker.com/v2/repositories"
auth = HTTPBasicAuth(DOCKER_USERNAME, DOCKER_PASSWORD)

def get_tags_page(page_url: str):
    resp = requests.get(page_url, auth=auth)
    resp.raise_for_status()
    return resp.json()

def delete_tag(tag_digest: str):
    url = f"{API_BASE}/{DOCKER_USERNAME}/{DOCKER_REPO}/manifests/{tag_digest}"
    resp = requests.delete(url, auth=auth)
    if resp.status_code == 202:
        print(f"Deleted tag manifest {tag_digest}")
    else:
        print(f"Failed to delete {tag_digest}: {resp.status_code} {resp.text}")

def main():
    tags_url = f"{API_BASE}/{DOCKER_USERNAME}/{DOCKER_REPO}/tags?page_size=100"
    while tags_url:
        data = get_tags_page(tags_url)
        tags_url = data.get("next", None)
        for tag in data["results"]:
            tag_name = tag["name"]
            if tag_name != "latest":
                digest = tag["images"][0]["digest"]
                print(f"Deleting tag {tag_name}")
                delete_tag(digest)

if __name__ == "__main__":
    print(f"Running cleanup for Docker Hub repository: {DOCKER_USERNAME}/{DOCKER_REPO}")
    main()
