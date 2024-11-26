To construct the `bom-ref`, `name`, and `purl` from a given `referenceLocator` in the format `"pkg:pypi/datadog@0.44.0"`, you can follow these rules:

1. **PURL**: The `purl` can be directly taken from the `referenceLocator`.
2. **bom-ref**: The `bom-ref` is similar to the `purl` but with the `/` and `@` symbols replaced by hyphens (`-`). For example, `"pkg:pypi/datadog@0.44.0"` would become `"pkg:pypi-datadog-0.44.0"`.
3. **Name**: The `name` is constructed by taking everything between the `/` and replacing the `/` with a colon (`:`). For example, from `"pkg:pypi/datadog@0.44.0"`, you would get `"pypi:datadog"`.

### Updated Full Script

Below is the complete Python script that implements this logic for generating an SBOM:

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

# Set up logging
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
    return re.sub(r'^[^0-9]*', '', version) if version else "unknown"

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
    
    for package in dependencies['sbom']['packages']:
        # Skip main repository, GitHub Actions, and related components
        if (package['name'] == repo_name or 
            package['name'] == f"com.github.{repo_name}" or 
            'actions/' in package['name'].lower() or 
            'github/actions' in package['name'].lower()):
            continue

        # Get referenceLocator which is expected to be in the format pkg:pypi/datadog@0.44.0
        reference_locator = package.get('referenceLocator')
        
        if reference_locator:
            # PURL is directly taken from referenceLocator
            purl = reference_locator
            
            # Construct bom-ref by replacing '/' and '@' with '-'
            bom_ref = purl.replace('/', '-').replace('@', '-')
            
            # Construct name by replacing '/' with ':'
            name = purl.split('/')[1].replace('/', ':')  # Extracting the package name
            
            # Extract version from referenceLocator if needed (after '@')
            version_info = reference_locator.split('@')[-1] if '@' in reference_locator else "unknown"

            components.append({
                "bom-ref": bom_ref,
                "type": "library",
                "name": f"{name}",
                "version": version_info,
                "purl": purl
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

def process_single_repo(owner, repo_name, access_token, output_base):
    g = Github(access_token)

    try:
        repo = g.get_repo(f"{owner}/{repo_name}")
        logging.info(f"Processing repository: {repo.full_name}")

        os.makedirs(output_base, exist_ok=True)

        repo_version = get_latest_release_version(repo)

        if repo_version:
            dependencies = get_dependencies(owner, repo.name, access_token)
            sbom_data = generate_sbom(dependencies, owner, repo.name, repo_version)
            output_file = os.path.join(output_base, f"{repo.name}.json")
            save_sbom_to_file(sbom_data, output_file)
        else:
            logging.info(f"No releases found for {repo.name}, using 'unknown' as version")
            dependencies = get_dependencies(owner, repo.name, access_token)
            sbom_data = generate_sbom(dependencies, owner, repo.name, "unknown")
            output_file = os.path.join(output_base, f"{repo.name}.json")
            save_sbom_to_file(sbom_data, output_file)

    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred for {repo.name}: {http_err}")
    except Exception as err:
        logging.error(f"An error occurred for {repo.name}: {err}")

if __name__ == "__main__":
    # Replace these values with your actual GitHub repository details and access token
    owner = "Eaton-Vance-Corp"
    repo_name = "your-repo-name"
    access_token = "your-github-access-token"
    output_base = r"c:\sre\sbom"

    process_single_repo(owner, repo_name, access_token, output_base)
```

### Key Changes Made:

1. **Reference Locator Handling**: The script now extracts the `referenceLocator` directly from the package data.
2. **PURL Construction**: The PURL is assigned directly from the `referenceLocator`.
3. **BOM Reference Construction**: The `bom-ref` replaces `/` and `@` with `-`.
4. **Name Construction**: The name is constructed by taking everything between the first `/` and replacing any further `/` with a colon (`:`).

### Usage Instructions:

- Replace `"your-repo-name"` with your actual GitHub repository name.
- Replace `"your-github-access-token"` with a valid GitHub access token.
- Adjust the `output_base` path as needed.

This script should now correctly generate an SBOM that meets your expectations based on the provided logic for constructing `bom-ref`, `name`, and `purl`. If you have any further adjustments or specific requirements you'd like to implement, feel free to ask!

Citations:
[1] https://cyclonedx.org/capabilities/bomlink/
[2] https://forums.autodesk.com/t5/inventor-forum/bom-structure-reference-component/td-p/8375983
[3] https://zt.dev/posts/analysis-spdx-sbom-generator/
[4] https://sysdig.com/blog/sbom-101-software-bill-of-materials/
[5] https://anchore.com/sbom/how-to-generate-an-sbom-with-free-open-source-tools/
[6] https://github.com/opensbom-generator/spdx-sbom-generator
[7] https://www.ntia.doc.gov/files/ntia/publications/ntia_sbom_formats_energy_brief_2021.pdf
[8] https://www.jit.io/resources/appsec-tools/a-guide-to-generating-sbom-with-syft-and-grype
