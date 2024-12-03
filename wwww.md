Here's the full workflow with the added debugging steps:

```yaml
name: CI

on:
  workflow_call:
    inputs:
      environment:
        description: "Environment to deploy (e.g., dev, qa)"
        required: true
        type: string
      branch:
        description: "Branch with Terraform to run"
        required: true
        type: string
      terraform_version:
        description: "Terraform version to install (e.g., 0.13.5)"
        required: true
        type: string
      working_directory:
        description: "Directory to run Terraform commands"
        required: true
        type: string

jobs:
  terraform:
    name: Terraform Workflow
    runs-on: ubuntu-latest
    environment: ${{ inputs.environment }}
    env:
      ARM_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
      ARM_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
      ARM_SUBSCRIPTION_ID: ${{ secrets.SUBSCRIPTION_ID }}
      ARM_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
      AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
      AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
      AZURE_SUBSCRIPTION_ID: ${{ secrets.SUBSCRIPTION_ID }}
      AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
      CWD: ${{ inputs.working_directory }}

    steps:
      # Install Azure CLI and PowerShell
      - name: Install Azure CLI and PowerShell
        run: |
          sudo rm -f /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
          sudo apt-get update
          sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
          sudo mkdir -p /etc/apt/keyrings
          curl -sLS https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /etc/apt/keyrings/microsoft.gpg > /dev/null
          sudo chmod go+r /etc/apt/keyrings/microsoft.gpg
          AZ_DIST=$(lsb_release -cs)
          echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ ${AZ_DIST} main" | sudo tee /etc/apt/sources.list.d/azure-cli.list
          sudo apt-get update
          sudo apt-get install -y azure-cli
          curl -LO https://github.com/PowerShell/PowerShell/releases/download/v7.4.5/powershell-7.4.5-1.deb_amd64.deb
          sudo dpkg -i powershell-7.4.5-1.deb_amd64.deb || sudo apt-get install -f -y
          rm -f powershell-7.4.5-1.deb_amd64.deb

      # Configure Git
      - name: Configure Git
        run: |
          git config --global credential.helper store
          echo "https://${{ secrets.GHA_RUNNERS_TOKEN }}:@github.com" > ~/.git-credentials

      # Checkout source code
      - name: Checkout Source Code
        uses: actions/checkout@v3
        with:
          ref: ${{ inputs.branch }}

      # Configure Terraform API Token
      - name: Configure Terraform API Token
        env:
          ARTIFACTORY_TOKEN: ${{ secrets.ARTIFACTORY_TOKEN }}
        run: |
          mkdir -p ~/.terraform.d
          cat <<EOF > ~/.terraform.d/credentials.tfrc.json
          {
            "credentials": {
              "frigate.jfrog.io": {
                "token": "${ARTIFACTORY_TOKEN}"
              }
            }
          }
          EOF

      # Configure Terraform RC File
      - name: Configure Terraform RC File
        run: |
          mkdir -p ~/.terraform.d
          cat <<EOF > ~/.terraformrc
          provider_installation {
              direct {
                  exclude = ["registry.terraform.io/*/*"]
              }
              network_mirror {
                  url = "https://frigate.jfrog.io/artifactory/api/terraform/tf-providers-ppa-azure/providers/"
              }
          }
          EOF

      # Verify .terraformrc contents
      - name: Verify .terraformrc contents
        run: cat ~/.terraformrc

      # Verify credentials.tfrc.json contents
      - name: Verify credentials.tfrc.json contents
        run: cat ~/.terraform.d/credentials.tfrc.json

      # Verify provider source
      - name: Verify provider source
        run: grep -R "source.*azurerm" .

      # Check Artifactory connectivity
      - name: Check Artifactory connectivity
        run: curl -I https://frigate.jfrog.io/artifactory/api/terraform/tf-providers-ppa-azure/providers/

      # Set up Terraform
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v1
        with:
          terraform_version: ${{ inputs.terraform_version }}
          terraform_wrapper: false

      # Show Terraform version
      - name: Echo Terraform Version
        run: terraform version

      # Initialize Terraform with verbose logging
      - name: Terraform Init
        id: init
        run: terraform init -backend-config="environments/${{ inputs.environment }}/backend.tfvars" -verbose

      # List provider cache
      - name: List provider cache
        run: ls -R ~/.terraform.d/providers

      # Validate Terraform configuration
      - name: Terraform Validate
        id: validate
        run: terraform validate

      # Plan Terraform deployment
      - name: Terraform Plan
        id: plan
        run: terraform plan -var-file="environments/${{ inputs.environment }}/main.tfvars"

      # Apply Terraform deployment
      - name: Terraform Apply
        working-directory: ${{ inputs.working_directory }}
        run: terraform apply -auto-approve -var-file="environments/${{ inputs.environment }}/main.tfvars"
```

This workflow includes all the original steps plus the additional debugging steps we discussed. These new steps will help you identify any issues with the Terraform configuration, Artifactory connectivity, or provider source specification.
