It seems that the search results do not contain any useful content or relevant information regarding your query about getting SBOM details for a single repository. However, I can provide you with a Python script that focuses on generating an SBOM for a single repository, including the EON_ID and checking for Angular 12 usage.

### Single Repository SBOM Generation Script

Here’s a complete script that generates an SBOM for a specified repository, retrieves the EON_ID, and checks if Angular 12 is being used:

```python
import requests
import json
import os
import logging
from github import Github
from github import GithubException
import pytz
import re

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Variable to easily switch between "EoNID" and "eon_id"
ID_PROPERTY_NAME = "eon_id"  # Change this to "EoNID" if needed

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

def get_repo_id(owner, repo, access_token):
    headers = {
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    properties_url = f"https://api.github.com/repos/{owner}/{repo}/properties/values"
    response = requests.get(properties_url, headers=headers)
    
    if response.status_code == 200:
        properties_data = response.json()
        for prop in properties_data:
            if prop.get("property_name") == ID_PROPERTY_NAME:
                return prop.get("value")
        logging.info(f"{ID_PROPERTY_NAME} not found for {repo}")
    else:
        logging.error(f"Error fetching properties for {repo}: {response.status_code}")
    
    return None

def check_angular_12(dependencies):
    for package in dependencies['sbom']['packages']:
        if package['name'] == 'npm:@angular/core' and package['versionInfo'].startswith('12.'):
            return True
    return False

def generate_sbom(dependencies, owner, repo):
    """
    Generates a comprehensive CycloneDX SBOM from the given dependencies.
    """
    logging.info(f"Generating comprehensive SBOM for {owner}/{repo}")

    sbom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(pytz.utc).isoformat(),
            "component": {
                "bom-ref": f"pkg:TRAINPACKAGE/{owner}/{repo}",
                "type": "application",
                "name": f"{owner}/{repo}",
                "version": get_latest_release_version(repo),  # You can implement this function similarly to before
                "purl": f"pkg:TRAINPACKAGE/{owner}/{repo}@{get_latest_release_version(repo)}"
            }
        },
        "components": []
    }

    # Add all packages to SBOM components
    for package in dependencies['sbom']['packages']:
        component = {
            "bom-ref": package.get('name'),
            "type": package.get('type', 'library'),  # Default type is library if not specified
            "name": package.get('name'),
            "version": package.get('versionInfo'),
            "purl": f"pkg:{package.get('name')}@{package.get('versionInfo')}"
        }
        
        sbom_data["components"].append(component)

    return sbom_data

def main():
    # Set up environment variables or hardcode values here
    org_name = os.environ.get('GITHUB_ORG_NAME')
    repo_name = os.environ.get('GITHUB_REPO_NAME')  # Specify the repository name here
    access_token = os.environ.get('GITHUB_TOKEN')

    try:
        dependencies = get_dependencies(org_name, repo_name, access_token)
        eon_id = get_repo_id(org_name, repo_name, access_token)
        sbom_data = generate_sbom(dependencies, org_name, repo_name)
        
        # Output the SBOM data to a JSON file
        output_file = f"{repo_name}_sbom.json"
        with open(output_file, 'w') as f:
            json.dump(sbom_data, f, indent=2)
        
        logging.info(f"SBOM generated successfully and saved to {output_file}")
        
        # Log the EON_ID value
        logging.info(f"EON_ID for {repo_name}: {eon_id}")
        
        # Check if Angular 12 is used
        uses_angular_12 = check_angular_12(dependencies)
        logging.info(f"Does the repository use Angular 12? {'Yes' if uses_angular_12 else 'No'}")

    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
    except Exception as err:
        logging.error(f"An error occurred: {err}")

if __name__ == "__main__":
    main()
```

### Key Features of This Script:

1. **Fetch Dependencies**: 
   - Uses GitHub's dependency graph API to fetch the SBOM of the specified repository.

2. **Retrieve EON_ID**: 
   - Fetches the EON_ID value from custom properties of the repository.

3. **Check for Angular 12 Usage**: 
   - Checks if the Angular framework version 12 is being used by examining the dependencies.

4. **Generate Comprehensive SBOM**: 
   - Constructs a CycloneDX-compliant SBOM that includes all packages and their details.

5. **Logging**: 
   - Provides detailed logs throughout the process for easier debugging and tracking.

6. **Output**: 
   - Saves the generated SBOM as a JSON file named after the repository (e.g., `repo_name_sbom.json`).

### Usage Instructions:

1. **Set Environment Variables**:
   - `GITHUB_ORG_NAME`: Your GitHub organization name.
   - `GITHUB_REPO_NAME`: The name of the specific repository you want to analyze.
   - `GITHUB_TOKEN`: Your GitHub personal access token with necessary permissions.

2. **Run the Script**:
   - Execute the script in your Python environment. It will generate an SBOM file and log relevant information about EON_ID and Angular usage.

### Conclusion:

This script allows you to focus on a single repository and gather comprehensive information about its dependencies while also checking for specific frameworks like Angular 12. It can be easily integrated into larger workflows or run independently as needed.

Citations:
[1] https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/11902716/6c18de5e-e231-414b-a391-fd96ab507e14/paste.txt
[2] https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/11902716/60a4ea87-4981-40b7-814b-d33852662eb0/paste-2.txt
