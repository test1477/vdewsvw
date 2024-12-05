Implementing a **Landing Zone (LZ)** and **Furnishing Zone (FZ)** requires a well-structured Terraform setup that organizes resources, modules, and values for clear separation of concerns. Below is a recommended **folder structure**, along with an approach to **fetch values from the Landing Zone for use in the Furnishing Zone**.

---

### **Conceptual Overview**
- **Landing Zone (LZ)**:
  - Focuses on core infrastructure components such as networking, resource groups, subnets, and governance.
  - These are foundational resources shared across environments.
  
- **Furnishing Zone (FZ)**:
  - Contains workload-specific resources such as databases, app services, or application dependencies.
  - These zones depend on values (e.g., VNet IDs, Subnet IDs, Key Vaults) provisioned by the Landing Zone.

---

### **Recommended Folder Structure**
```plaintext
terraform/
├── landing-zone/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── state/
│   │   ├── dev/
│   │   ├── qa/
│   │   └── prod/
│   ├── modules/
│   │   ├── networking/
│   │   ├── resource-groups/
│   │   ├── governance/
│   │   └── security/
│   └── environments/
│       ├── dev/
│       │   ├── backend.tf
│       │   └── terraform.tfvars
│       ├── qa/
│       │   ├── backend.tf
│       │   └── terraform.tfvars
│       └── prod/
│           ├── backend.tf
│           └── terraform.tfvars
├── furnishing-zone/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── state/
│   │   ├── dev/
│   │   ├── qa/
│   │   └── prod/
│   ├── modules/
│   │   ├── app-services/
│   │   ├── databases/
│   │   ├── monitoring/
│   │   └── storage/
│   └── environments/
│       ├── dev/
│       │   ├── backend.tf
│       │   └── terraform.tfvars
│       ├── qa/
│       │   ├── backend.tf
│       │   └── terraform.tfvars
│       └── prod/
│           ├── backend.tf
│           └── terraform.tfvars
```

---

### **Implementation Steps**

#### **Step 1: Define Outputs in the Landing Zone**
In `landing-zone/outputs.tf`, define the values you want to share with the Furnishing Zone.

```hcl
output "vnet_id" {
  value = module.networking.vnet_id
}

output "subnet_ids" {
  value = module.networking.subnet_ids
}

output "key_vault_id" {
  value = module.security.key_vault_id
}
```

---

#### **Step 2: Store the State File of the Landing Zone**
Ensure the Landing Zone uses a remote backend (e.g., Azure Storage) to store its state, enabling the Furnishing Zone to fetch its outputs.

Example `backend.tf` for the Landing Zone:
```hcl
terraform {
  backend "azurerm" {
    resource_group_name  = "tfstate-rg"
    storage_account_name = "tfstateprod"
    container_name       = "landing-zone"
    key                  = "terraform.tfstate"
  }
}
```

---

#### **Step 3: Reference Landing Zone Outputs in the Furnishing Zone**
Use a **data source** in the Furnishing Zone to fetch the Landing Zone’s state file.

Example `furnishing-zone/main.tf`:
```hcl
data "terraform_remote_state" "landing_zone" {
  backend = "azurerm"
  config = {
    resource_group_name  = "tfstate-rg"
    storage_account_name = "tfstateprod"
    container_name       = "landing-zone"
    key                  = "terraform.tfstate"
  }
}

module "app_services" {
  source      = "./modules/app-services"
  vnet_id     = data.terraform_remote_state.landing_zone.outputs.vnet_id
  subnet_id   = data.terraform_remote_state.landing_zone.outputs.subnet_ids["app-subnet"]
  key_vault_id = data.terraform_remote_state.landing_zone.outputs.key_vault_id
}
```

---

#### **Step 4: Separate State for Furnishing Zone**
Use a similar backend setup for the Furnishing Zone to store its state separately.

Example `backend.tf` for Furnishing Zone:
```hcl
terraform {
  backend "azurerm" {
    resource_group_name  = "tfstate-rg"
    storage_account_name = "tfstateprod"
    container_name       = "furnishing-zone"
    key                  = "terraform.tfstate"
  }
}
```

---

#### **Step 5: Create Environment-Specific Configurations**
Define environment-specific `terraform.tfvars` for each zone.

Example `landing-zone/environments/dev/terraform.tfvars`:
```hcl
vnet_name    = "dev-vnet"
subnets      = ["dev-app-subnet", "dev-db-subnet"]
key_vault_id = "/subscriptions/.../keyvaults/dev-kv"
```

Example `furnishing-zone/environments/dev/terraform.tfvars`:
```hcl
app_service_name = "dev-app-service"
database_name    = "dev-db"
```

---

### **Workflow**
1. **Deploy Landing Zone**:
   - Navigate to the `landing-zone/environments/dev` folder.
   - Run:
     ```bash
     terraform init
     terraform apply -var-file="terraform.tfvars"
     ```

2. **Deploy Furnishing Zone**:
   - Navigate to the `furnishing-zone/environments/dev` folder.
   - Run:
     ```bash
     terraform init
     terraform apply -var-file="terraform.tfvars"
     ```

3. The Furnishing Zone will dynamically fetch values from the Landing Zone’s state.

---

### **Key Points**
1. **Isolation of State**:
   - Keep separate state files for the Landing Zone and Furnishing Zone for better modularity and reduced risk of conflicts.
   
2. **Dependencies**:
   - Use `terraform_remote_state` data sources in the Furnishing Zone to access Landing Zone outputs.

3. **Environment Consistency**:
   - Align variable definitions across environments for consistent deployments.

This setup ensures a clean separation between core infrastructure (Landing Zone) and application-specific resources (Furnishing Zone) while allowing easy reuse and maintenance.
