###################################################################################################
# Global Scoped Variables cGFzaGE=
param($param)
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

$hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online
$wsl = Get-WindowsOptionalFeature -FeatureName Microsoft-Windows-Subsystem-Linux -Online

# Getting Path Entries cGFzaGE=
$Sytem_Path= [System.Environment]::GetEnvironmentVariable("Path", "Machine").split(';')
$User_Path=[System.Environment]::GetEnvironmentVariable("Path", "User").split(';')

function logo{
  
  Write-Host("`n`n## K3D Auto-Deploy Script ##") -ForegroundColor Red # UGFzaGEK
  
  }
  
  function sys_check{
  
  Write-Host "`n-------------------------------------------" -ForegroundColor Green
  Write-Host "## Checking System Resources ##" -ForegroundColor Green #cGFzaGE=
  Write-Host "-------------------------------------------`n" -ForegroundColor Green
  
  $cpu = (Get-CimInstance -ClassName Win32_Processor | Select-Object -Property Name, NumberOfCores)
  $osnram = (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property Caption, Version, OsArchitecture, TotalVisibleMemorySize, FreePhysicalMemory)
  $wsl_state = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
  $processor = $cpu.Name[0]
  $corecount = ($cpu.NumberOfCores)
  $corecount = $corecount[0]+$corecount[1]
  $os = $osnram.Caption
  $osver = $osnram.Version
  $ostype = $osnram.OsArchitecture
  $totalram = $osnram.TotalVisibleMemorySize / 1mb
  $ram = [math]::ceiling(($totalram)) 
  #Wsl Dependent Variables
  $wsl_config_file = $home+"\.wslconfig"
  
  Write-Host "Processor : $processor"
  Write-Host "Cores     : $corecount"
  
      if ($ram -ne "32"){
          Write-Host "Ram       : $ram GB - Memory Doesn't meet the Requirement"
          Start-Sleep 7
          $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
          exit
      }
      else{
          Write-Host "Ram       : $ram GB"
      }
  
  Write-Host "OS        : $os"
  Write-Host "Build     : $osver"
  Write-Host "Type      : $ostype"
  Write-Host "`n"
  Write-Host $wsl_state.DisplayName": "$wsl_state.State
  
      if ($wsl_state.State -ne "Enabled"){
  
          Write-Host "`n WSL is not Enabled, Unable to Proceed, Try again after enabling WSL 2`n"
          Start-Sleep 7
          $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
          exit
  
      }
  
      if($wsl_config_file){
  
          $wsl_proc_check =((Get-Content $wsl_config_file | Where {$_ -match 'processors=4'}).split(" ")[0]).split("=")[1]
          $wsl_memory_check =((Get-Content $wsl_config_file | Where {$_ -match 'memory=20GB'}).split(" ")[0]).split("=")[1]
  
          if ($wsl_memory_check -eq "20GB" -and $wsl_proc_check -eq "4" ){
              
              Write-Host "`n>> WSL Config Info"
              Write-Host 'Processor :'$wsl_proc_check'Cores'
  
              if ($wsl_memory_check -ne "20GB"){ Write-Host "Memory    : $wsl_memory_check Memory Doesn't meet the Requirement" }
              
              else{ Write-Host "Memory    : $wsl_memory_check`n" }
        
          }
  
      }
      else{ Write-Host "Note: WSL Config not found" -ForegroundColor Red # UGFzaGEK 
    }
  
}

function wsl_conversion{

    Write-Host "`n-------------------------------------------" -ForegroundColor Green
    Write-Host "## Setting-up Environment to Deploy ##" -ForegroundColor Green
    Write-Host "-------------------------------------------`n" -ForegroundColor Green

    Write-Host("`nInitiating WSL 2 Conversion `n")

    $job = Start-Job {wsl --set-version Ubuntu 2} #cGFzaGE=

    Wait-Job $job

    Receive-Job $job

    Write-Host "`nSetting Ubuntu-22.04 root user as Default"

    ubuntu config --default-user root

}

function wsl_default{

    Write-Host("`nMaking sure, Ubuntu is set to WSL Default`n")

    wsl -s Ubuntu
    Write-Host "Set-up : Done"

    ubuntu2204 config --default-user root
    Write-Host "Sucessfully set default user as root"

}

function wsl_install{

    # start powershell{wsl -- npm start; Read-Host

    # start-process -FilePath powershell.exe -ArgumentList"wsl --install -d Ubuntu" -Wait -NoNewWindow

    Write-Host "`n-------------------------------------------" -ForegroundColor Green
    Write-Host "## Initializing WSL Ubuntu ##" -ForegroundColor Green
    Write-Host "-------------------------------------------" -ForegroundColor Green

    $job = Start-Job { wsl --install -d Ubuntu} | Out-Null # cGFzaGE=

    Start-Sleep -Seconds 17;

    ubuntu config --default-user johndoe

    Stop-Process -Name "ubuntu"

    # $job = Start-Job { wsl --install -d Ubuntu --no-launch} | Out-Null
    
    wsl_default

    wsl_conversion

}

function wsl_checks{

    ### Execution Block Startin
    $x = (wsl -l -v).split(" ") | where{$_ -ne ""} | where{$_ -eq "Ubuntu"}

        If ($x){

            Write-Host "Ubuntu is available in the system"
        }
        else {

            Write-Host "`nUbuntu is not available, Installing it now, Please wait."
            wsl_install
        }

    #################################################################################
        
    $x = (((wsl -l -v | where{$_ -ne ""})[1]).split(" ") | where { $_ -ne "" })


    #For Ubuntu-20.04 check 
    $y = $x[1] | where { $_ -eq "Ubuntu"}

        If ($y){

            Write-Host "Ubuntu is Set as Default"

        }
        else {

            Write-Host "Ubuntu is not Default"
            wsl_default

        }

    #For WSL Version check 

    $y = $x[3] | where { $_ -eq "2"}

        If ($y){

            Write-Host "Ubuntu is using WSL2"

        }
        else{

            wsl_conversion
        }

}

function clear_ubuntu{ 
    wsl --unregister Ubuntu
}

function initialize_ubuntu{

    Write-Host("`nMaking Sure Ubuntu is up to date, this may take a few minutes... `n")
    Write-Host "`n>> Updating" -ForegroundColor Red
    wsl -u root -d Ubuntu apt-get update -y
    Write-Host "`n>> Installing Unzip" -ForegroundColor Red
    wsl -u root -d Ubuntu apt install unzip -y

}

function install_docker_wsl{

Write-Host "`n>> Installing Docker-ce Wsl" -ForegroundColor Red
wsl -u root -d Ubuntu bash -c "apt-get update"
wsl -u root -d Ubuntu bash -c "apt-get install -y ca-certificates curl gnupg lsb-release"

$x = wsl -u root -d Ubuntu bash -c "ls -al  /etc/apt/keyrings | grep -i 'docker.gpg'"

if($x){
    wsl -u root -d Ubuntu bash -c "rm  /etc/apt/keyrings/docker.gpg"
}

wsl -u root -d Ubuntu bash -c "mkdir -p /etc/apt/keyrings"
wsl -u root -d Ubuntu bash -c "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg"

wsl -u root -d Ubuntu bash -c "echo 'deb [arch=$`(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $`(lsb_release -cs) stable' | tee /etc/apt/sources.list.d/docker.list > /dev/null"

wsl -u root -d Ubuntu bash -c "apt-get update"

wsl -u root -d Ubuntu bash -c "chmod a+r /etc/apt/keyrings/docker.gpg"
wsl -u root -d Ubuntu bash -c "apt-get update &`&` apt-get upgrade -y"

wsl -u root -d Ubuntu bash -c "apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin"

wsl -u root -d Ubuntu bash -c "usermod -aG docker $`{USER}"

wsl -u root -d Ubuntu bash -c "update-alternatives --set iptables /usr/sbin/iptables-legacy"

wsl -u root -d Ubuntu bash -c "service docker start" 

}

function flush_docker_wsl{

    wsl -u root -d Ubuntu bash -c "apt-get purge -y docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-ce-rootless-extras"

    wsl -u root -d Ubuntu bash -c " rm -rf /var/lib/docker"
    wsl -u root -d Ubuntu bash -c " rm -rf /var/lib/containerd"
    wsl -u root -d Ubuntu bash -c " rm -rf /etc/apt/keyrings"
}

function install_helm{

    $check_helm = wsl -u root -d Ubuntu bash -c 'helm version 2>/dev/null'
    
    if ($check_helm){
        write-host "Helm is Installed"
    }
    else {

        Write-Host "`n>> Installing Helm 3" -ForegroundColor Red
        wsl -u root -d Ubuntu bash -c "curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash"

        $check_helm = wsl -u root -d Ubuntu bash -c 'helm version 2>/dev/null'

        if($check_helm){

            Write-Host 'Helm successfully installed'

        }

        else{

            Write-Host 'Helm install failed'

        }
    }
    

}

function install_kubectl{

    $check_kubectl = wsl -u root -d Ubuntu bash -c 'kubectl version 2>/dev/null'
    
    if ($check_kubectl){
        write-host "Kubectl is Installed"
    }
    else {

        Write-Host "`n>> Installing Kubectl" -ForegroundColor Red
        wsl -u root -d Ubuntu bash -c "curl -LO 'https://dl.k8s.io/release/$`(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl'; install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl"

        $check_kubectl = wsl -u root -d Ubuntu bash -c 'kubectl version 2>/dev/null'

        if($check_kubectl){

            Write-Host 'Kubectl successfully installed'

        }

        else{

            Write-Host 'Kubectl install failed'

        }
    }

}

function install_k3d{

    $k3d_check = wsl -u root -d Ubuntu bash -c "k3d version 2>/dev/null"  

    if($k3d_check){
        
        Write-Host "k3d is installed"    

    }        
    else{
        
        Write-Host "`n>> Installing K3d" -ForegroundColor Red
        wsl -u root -d Ubuntu bash -c "curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash"

        $k3d_check = wsl -u root -d Ubuntu bash -c "k3d version 2>/dev/null"
        
        if($k3d_check){

            Write-Host 'K3d successfully installed'

        }

        else{

            Write-Host 'K3d install failed try running the script with admin rights'

        }

    }

}

function initialize_k3d{
    
    Write-Host "`n>> Initializing k3d dev Cluster" -ForegroundColor Red
    wsl -u root -d Ubuntu bash -c "k3d cluster create x --agents 1 --wait --port 8443:8443@loadbalancer --k3s-arg --disable=traefik@server:0" # cGFzaGE=
    
    #wsl -u root -d Ubuntu bash -c "k3d cluster create dev --agents 1 --wait --port 8080:8080@loadbalancer --port 6443:8443@loadbalancer --port 7080:80@loadbalancer --port 7443:443@loadbalancer --k3s-arg --disable=traefik@server:0 `&`& sleep 17"

}

function init_edge_stack{

wsl -u root -d Ubuntu bash -c "rm -rf /tmp/ssl"

wsl -u root -d Ubuntu bash -c "mkdir /tmp/ssl `&`& chmod 777 /tmp/ssl"

wsl -u root -d Ubuntu bash -c "kubectl create ns ambassador"

wsl -u root -d Ubuntu bash -c "openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -keyout /tmp/ssl/cert.key -out /tmp/ssl/cert.crt -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' -addext 'extendedKeyUsage=serverAuth,clientAuth'"

wsl -u root -d Ubuntu bash -c "cp -r /tmp/ssl ."

wsl -u root -d Ubuntu bash -c "kubectl create secret tls edge-stack-tls --cert=/tmp/ssl/cert.crt --key=/tmp/ssl/cert.key -n ambassador"

# kubectl create secret tls "$TLSName" " --key "$YourCertificateName.key" --cert "$YourCertificateName.crt" --dry-run='client' -o='yaml' >> "$YourCertificateName.yaml"

Write-Host "`n>> Deploying Edge-Stack Ingress" -ForegroundColor Red

wsl -u root -d Ubuntu bash -c "helm repo add datawire https://app.getambassador.io `&`& helm repo update"

wsl -u root -d Ubuntu bash -c "kubectl apply -f https://app.getambassador.io/yaml/edge-stack/3.4.0/aes-crds.yaml"

wsl -u root -d Ubuntu bash -c "kubectl wait --timeout=90s --for=condition=available deployment emissary-apiext -n emissary-system"

wsl -u root -d Ubuntu bash -c "cat <<EOF | helm upgrade edge-stack --namespace ambassador datawire/edge-stack --install -f -
fullnameOverride: edge-stack
emissary-ingress:
  service:
    type: LoadBalancer
    ports:
    - name: http
      port: 8080
      targetPort: 8080
    - name: https
      port: 8443
      targetPort: 8443
---
EOF" 

wsl -u root -d Ubuntu bash -c "kubectl -n ambassador wait --for condition=available --timeout=90s deploy -lproduct=aes"

# Deploying Secure Listener
wsl -u root -d Ubuntu bash -c "cat <<EOF | kubectl apply -f -
---
apiVersion: getambassador.io/v3alpha1
kind: Listener
metadata:
    name: edge-stack-listener-8080
    namespace: ambassador
spec:
    port: 8080
    protocol: HTTP
    securityModel: XFP
    hostBinding:
      namespace:
        from: ALL
---
apiVersion: getambassador.io/v3alpha1
kind: Listener
metadata:
    name: edge-stack-listener-8443
    namespace: ambassador
spec:
    port: 8443
    protocol: HTTPS
    securityModel: XFP
    hostBinding:
      namespace:
        from: ALL
---
EOF"

# Deploying Secure Host
wsl -u root -d Ubuntu bash -c "cat <<EOF | kubectl apply -f -
apiVersion: getambassador.io/v2
kind: Host
metadata:
  labels:
    app.kubernetes.io/managed-by: Helm
  name: ambassador-host
  namespace: ambassador
spec:
#   ambassador_id: edge-stack
#   acmeProvider:
#     authority: none
  hostname: '*'
#   requestPolicy:
#     insecure:
#       action: Redirect
#       additionalPort: 8080
  tls:
    min_tls_version: v1.2
  tlsSecret:
    name: edge-stack-tls
---
EOF"

Write-Host "`n>> Deploying Quote Backend" -ForegroundColor Red

wsl -u root -d Ubuntu bash -c "kubectl create ns quote `&`& kubectl apply -f https://app.getambassador.io/yaml/v2-docs/3.4.0/quickstart/qotm.yaml -n quote"

# Deploying Mappings
wsl -u root -d Ubuntu bash -c "cat <<EOF | kubectl apply -n quote -f -
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: quote-backend
  namespace: quote
spec:
  hostname: '*'
  prefix: /backend
  rewrite: /
  service: quote.quote
  docs:
    path: '/.ambassador-internal/openapi-docs'
---
EOF"



}

function init_db_charts{

Write-Host "`n>> Deploying Postgres & Pgadmin" -ForegroundColor Red

wsl -u root -d Ubuntu bash -c "helm repo add bitnami https://charts.bitnami.com/bitnami `&`& helm repo add runix https://helm.runix.net `&`& helm repo update" 

wsl -u root -d Ubuntu bash -c "kubectl create ns appdb"

wsl -u root -d Ubuntu bash -c "cat <<EOF | helm upgrade postgres bitnami/postgresql --namespace appdb --wait --install -f -
fullnameOverride: postgres
global:
  storageClass: `"local-path`"
  postgresql:
    auth:
      enablePostgresUser: true
      postgresPassword: 'postgres'
      database: postgres
    service:
      ports:
        postgresql: 5432
resources:
  requests:
    cpu: 50m
    memory: 100Mi
  limits:
    cpu: 100m
    memory: 256Mi
primary:
  extraEnvVars:
    - name: HOME
      value: '/bitnami/postgresql/data'
    - name: PGHOST
      value: 'localhost'
    - name: PGSSLMODE
      value: 'prefer'
  initdb:
    scripts:
      db-init.sql: |
        CREATE DATABASE `"elasticsearch`" WITH OWNER = `"postgres`" TABLESPACE = pg_default CONNECTION LIMIT = -1;
        CREATE DATABASE `"keycloak`" WITH OWNER = `"postgres`" TABLESPACE = pg_default CONNECTION LIMIT = -1;
        CREATE DATABASE `"kafka`" WITH OWNER = `"postgres`" TABLESPACE = pg_default CONNECTION LIMIT = -1;
        CREATE DATABASE `"prometheus`" WITH OWNER = `"postgres`" TABLESPACE = pg_default CONNECTION LIMIT = -1;
        CREATE DATABASE `"argocd`" WITH OWNER = `"postgres`" TABLESPACE = pg_default CONNECTION LIMIT = -1;
        CREATE DATABASE `"webapp`" WITH OWNER = `"postgres`" TABLESPACE = pg_default CONNECTION LIMIT = -1;
---
EOF"

wsl -u root -d Ubuntu bash -c "cat <<EOF | helm upgrade pgadmin runix/pgadmin4 --version 1.13.6 --namespace appdb --install --set fullnameOverride=pgadmin -f -
serverDefinitions:
  enabled: true
  servers:
    firstServer:
      Name: `"appdb`"
      Group: `"Servers`"
      Port: 5432
      Username: `"postgres`"
      Host: `"postgres`"
      SSLMode: `"prefer`"
      MaintenanceDB: `"postgres`"
env:
  email: admin@pgadmin.com
  password: admin
---
EOF"


wsl -u root -d Ubuntu bash -c "cat <<EOF | kubectl apply -n appdb -f -
---
apiVersion: getambassador.io/v2
kind:  Mapping
metadata:
  name:  pgadmin-login
spec:
  prefix: /pgadmin/authenticate/login
  rewrite: /pgadmin/authenticate/login
  service: pgadmin
  host: localhost:8443
  add_request_headers:
    X-Script-Name: /pgadmin
    X-Forwarded-Proto: https
  add_response_headers:
    location:
      append: False
      value: https://localhost:8443/pgadmin
  bypass_auth: true
---
apiVersion: getambassador.io/v2
kind:  Mapping
metadata:
  name:  pgadmin-mapping
spec:
  prefix: /pgadmin
  rewrite: /pgadmin
  service: pgadmin
  host: localhost:8443
  add_request_headers:
    X-Script-Name: /pgadmin
    X-Forwarded-Proto: https
  bypass_auth: true
---
EOF"

}

function init_x{

Write-Host "`n>> Deploying x-Server" -ForegroundColor Red

wsl -u root -d Ubuntu bash -c "cp ./charts/x-12.0.0.tgz /tmp"

wsl -u root -d Ubuntu bash -c "cat <<EOF | helm upgrade x /tmp/x-12.0.0.tgz -n x --create-namespace --wait --install -f -
namespace: x
fullnameOverride: `"x`"
storageClass: `"local-path`"
service:
  type: ClusterIP
  port: 8080
x:
  admin:
    group: `"x`"
  rds:
    provider: `"POSTGRESQL`"
    endpoint: `"postgres.appdb`"
    port: `"5432`"
    user: `"postgres`"
    password: `"postgres`"
    schema: `"x`"
    initOrUpgrade: `"YES`"
  persistentVolume:
    enabled: false
  xDiagnostics:
    persistentVolume:
      enabled: false
  createDocumentServer: `"YES`"
  defaultSSOKey: `"ADASDFASDFXGGEG25585`"
---
EOF"   

}

function remove_k3d{

    Write-Host "`n>> Deleting k3d x Cluster" -ForegroundColor Red
    wsl -u root -d Ubuntu bash -c "k3d cluster delete x"

}

function k3d_image_import{

    Write-Host "`n>> Importing Images" -ForegroundColor Red
    wsl -u root -d Ubuntu bash -c "pwd"
    wsl -u root -d Ubuntu bash -c "k3d image import ./docker-images/x-docker-image.tar -c dev"

}

function install_cert{
    Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match 'localhost' -and $_.Issuer -match 'localhost' } | Remove-Item
    Import-Certificate -FilePath (${pwd}.Path+"\ssl\cert.crt") -CertStoreLocation Cert:\LocalMachine\Root

}

$help = @"
#################################################

Example
-------

cGFzaGE=\example-win-directory> .\script-name.ps1 --argument

#################################################

Checks & Installation Args
--------------------------

'--sys-check'        - Does a System Check for k8s requirment
'--auto-deploy'      - Initiates complete deployment automatically 
'--init-wsl'         - Installs WSL Ubuntu Distro on the Windows Host
'--init-docker-wsl'  - Installs docker-ce in the WSL Distro
'--init-helm-wsl'    - Installs Helm in WSL Distro
'--init-kubectl-wsl' - Installs Kubectl in WSL Distro
'--init-k3d-wsl'     - Installs K3d in WSL Distro
'--init-db'          - Installs Postgresql DB in WSL Distro
'--init-edge-stack'  - Installs Ambassador Edge-Stack Ingress in WSl Distro
'--install-cert'     - Installs Self Signed Certificate inside of the Windows Host

#################################################

Infra Management Args
---------------------

'--load-k3d-images'  - Loads docker image .tar files into K3d Cluster
'--start-k3d'        - Starts k3d Cluster
'--stop-k3d'         - Stops k3d Cluster

#################################################

Delete Args
-----------

'--flush-k3d'        - Removes k3d completely from the WSL Distro
'--flush-wsl'        - Removes WSL Distro Completely from Windows Host
'--flush-docker-wsl' - Remove Docker-ce from WSL Distro

#################################################
"@

## Execution Block
if ($param -eq "--sys-check"){ logo; sys_check }
elseif ($param -eq "--start-k3d"){ start_cluster }
elseif ($param -eq "--stop-k3d"){ stop_cluster }
elseif ($param -eq "--auto-deploy"){ auto }
elseif ($param -eq "--init-wsl"){ wsl_checks; initialize_ubuntu }
elseif ($param -eq "--init-docker-wsl"){ install_docker_wsl }
elseif ($param -eq "--init-helm-wsl"){ install_helm }
elseif ($param -eq "--init-kubectl-wsl"){ install_kubectl }
elseif ($param -eq "--init-k3d-wsl"){ install_k3d }
elseif ($param -eq "--init-charts"){ init_charts }
elseif ($param -eq "--init-dev"){ initialize_k3d }
elseif ($param -eq "--init-db"){ init_db_charts }
elseif ($param -eq "--init-edge-stack"){ init_edge_stack }
elseif ($param -eq "--init-auth"){ init_auth }
elseif ($param -eq "--init-pv"){ init_pv }
elseif ($param -eq "--install-cert"){ install_cert }
#################################################
elseif ($param -eq "--flush-k3d"){ remove_k3d }
elseif ($param -eq "--flush-wsl"){ clear_ubuntu }
elseif ($param -eq "--flush-docker-wsl"){ flush_docker_wsl }
#################################################
elseif ($param -eq "--load-k3d-images"){ k3d_image_import }
else { Write-Host $help }
