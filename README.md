Certainly! Here's the full updated script incorporating all the changes we've discussed, including the fix for the version duplication issue:

```python
import requests
import json
import os
import logging
from github import Github
from github import GithubException
from datetime import datetime
import pytz
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_dependencies(owner, repo, access_token):
    logging.info(f"Fetching dependencies for repo: {owner}/{repo}")
    url = f"https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom"
    headers = {
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github+json"
    }
    response = requests.get(url, headers=headers)
    logging.info(f"GitHub API response status: {response.status_code}")
    response.raise_for_status()
    logging.info("Successfully fetched dependencies.")
    return response.json()

def get_latest_release_version(repo):
    try:
        latest_release = repo.get_latest_release()
        version = latest_release.tag_name
        return version[1:] if version.startswith('v') else version
    except GithubException:
        logging.warning(f"No releases found for {repo.full_name}")
        return None

def clean_version(version):
    if not version:
        return "unknown"
    version = version.encode('utf-8').decode('unicode_escape')
    version = re.sub(r'^[^a-zA-Z0-9]+', '', version)
    # Add space after comma and before < or > if not present
    version = re.sub(r',\s*([<>])', r', \1', version)
    return version

def generate_sbom(dependencies, owner, repo, repo_version):
    logging.info(f"Generating SBOM for {owner}/{repo}")
    
    repo_name = f"{owner}/{repo}"
    
    metadata_component = {
        "bom-ref": f"pkg:TRAINPACKAGE/{repo_name}",
        "type": "application",
        "name": repo_name,
        "version": repo_version,
        "purl": f"pkg:TRAINPACKAGE/{repo_name}@{repo_version}"
    }
    
    components = []
    for package in dependencies['sbom'].get('packages', []):
        purl = next((ref['referenceLocator'] for ref in package.get('externalRefs', []) 
                     if ref.get('referenceType') == 'purl'), None)
        
        if purl and not (purl.startswith('pkg:github') or 
                         purl.startswith('pkg:githubactions') or 
                         purl.startswith('pkg:actions')):
            name = package.get('name')
            version = clean_version(package.get('versionInfo'))
            
            # Check if version is already in purl
            if '@' in purl:
                purl_parts = purl.split('@')
                purl_without_version = purl_parts[0]
                version = purl_parts[1]  # Use version from purl
                purl_with_version = purl  # Use original purl
            else:
                purl_without_version = purl
                purl_with_version = f"{purl}@{version}"
            
            # Construct bom-ref
            pkg_parts = purl_without_version.split('/', 2)
            if len(pkg_parts) >= 2:
                bom_ref = f"{pkg_parts[0]}-{pkg_parts[1]}"
                if len(pkg_parts) == 3:
                    bom_ref += f"/{pkg_parts[2]}"
                bom_ref += f"-{version}"
            else:
                bom_ref = f"{purl_without_version}-{version}"
            
            bom_ref = bom_ref.replace('@', '-')
            
            components.append({
                "bom-ref": bom_ref,
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl_with_version
            })

    eastern = pytz.timezone('US/Eastern')
    timestamp = datetime.now(eastern).isoformat(timespec='seconds')

    sbom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": metadata_component
        },
        "components": components
    }

    return sbom_data

def save_sbom_to_file(sbom_data, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(sbom_data, f, indent=2)
        logging.info(f"SBOM exported successfully to {filename}")
    except Exception as e:
        logging.exception(f"Error saving SBOM to {filename}")

def process_single_repository(owner, repo_name, access_token, output_base):
    g = Github(access_token)
    
    try:
        repo = g.get_repo(f"{owner}/{repo_name}")
        logging.info(f"Successfully accessed repository: {repo.full_name}")
        
        os.makedirs(output_base, exist_ok=True)
        
        repo_version = get_latest_release_version(repo)
        if repo_version:
            dependencies = get_dependencies(owner, repo_name, access_token)
            sbom_data = generate_sbom(dependencies, owner, repo_name, repo_version)
            output_file = os.path.join(output_base, f"{repo_name}.json")
            save_sbom_to_file(sbom_data, output_file)
        else:
            logging.info(f"Skipping {repo_name} as it has no releases")
    
    except GithubException as e:
        logging.exception(f"Error accessing repository {owner}/{repo_name}")
    except Exception as e:
        logging.exception("Error processing repository")

if __name__ == "__main__":
    owner = "example-owner"
    repo_name = "example-repo"
    access_token = "your-github-access-token"
    output_base = r"c:\sre\sbom"

    process_single_repository(owner, repo_name, access_token, output_base)
```

This script now includes all the modifications we've discussed, including:

1. Fetching dependencies for a single GitHub repository.
2. Generating a CycloneDX SBOM with components populated from the packages in the dependency data.
3. Excluding GitHub Actions components.
4. Handling version ranges and special characters in version strings.
5. Including the version in both the `bom-ref` and `purl` fields for each component.
6. Using the package name directly from the `name` field.
7. Preserving commas and adding spaces in version strings as requested.
8. Formatting the `bom-ref` as requested, only replacing the first '/' after 'pkg:' with a '-'.
9. Preventing duplication of versions in both the `purl` and `bom-ref` fields.
10. Saving the generated SBOM as a JSON file in the specified output directory.

To use this script:

1. Replace the placeholder values in the `if __name__ == "__main__":` block with your actual GitHub repository details and access token.
2. Ensure you have the required Python libraries installed (`requests`, `PyGithub`, `pytz`).
3. Run the script to generate an SBOM for the specified repository.

This script should now correctly handle various version formats, including ranges with proper spacing, and avoid duplicating versions in the `purl` and `bom-ref` fields.
