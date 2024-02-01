###################################################################################################
# Global Scoped Variables
param($param)
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

$hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online
$wsl = Get-WindowsOptionalFeature -FeatureName Microsoft-Windows-Subsystem-Linux -Online

# Getting Path Entries
$Sytem_Path= [System.Environment]::GetEnvironmentVariable("Path", "Machine").split(';')
$User_Path=[System.Environment]::GetEnvironmentVariable("Path", "User").split(';')

function logo{

  Write-Host("`n`n## K3D Auto-Deploy Script ##") -ForegroundColor Red # UGFzaGEK
  
  }
  
  function sys_check{
  
  Write-Host "`n-------------------------------------------" -ForegroundColor Green
  Write-Host "## Checking System Resources ##" -ForegroundColor Green
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
              
              Write-Host "`n>> WSL Config Info`n"
              Write-Host 'Processor :'$wsl_proc_check'Cores'
  
              if ($wsl_memory_check -ne "20GB"){ Write-Host "Memory    : $wsl_memory_check Memory Doesn't meet the Requirement" }
              
              else{ Write-Host "Memory    : $wsl_memory_check" }
        
          }
  
      }
      else{ Write-Host "Note: WSL Config not found" }
  
  }
  

function docker{

    
    $og_path = ${pwd}.Path
    $var1 = docker ps 2>$null
    if(-not (Test-Path "C:\Program Files\Docker\Docker\Docker Desktop.exe") -and -not($var1)){

        if (-not (Test-Path DockerInstaller.exe))
            {
                
                Write-Host "Downloading the Docker exe"
                Invoke-WebRequest -Uri https://desktop.docker.com/win/stable/Docker%20Desktop%20Installer.exe -OutFile DockerInstaller.exe -UseBasicParsing
                Write-Host "Download Completed"
            } 
                Write-Host "Installing Docker..."
                start-process .\DockerInstaller.exe "install --quiet --accept-license --Skip-tutorial" -Wait -NoNewWindow
                Write-Host "Docker Installed successfully"
                $env:Path += ";C:\Program Files\Docker\Docker\Resources\bin"
                $env:Path += ";C:\Program Files\Docker\Docker\Resources"
                
                
                # Write-Host "You must reboot the sytem to continue. After reboot re-run the script."
                # Restart-Computer -Confirm 
            
    }
    if (Test-Path "C:\Program Files\Docker\Docker\Docker Desktop.exe"){

    $var1 = docker ps 2>$null
    if (-not $var1){

        cd "C:\Program Files\Docker\Docker\"
        $ProgressPreference = 'SilentlyContinue'
        Write-Host "Starting docker..."
        & '.\Docker Desktop.exe'
        #& '.\Docker Desktop.exe' -ArgumentList "/S" -PassThru
        #Start-Process -WindowStyle Minimized '.\Docker Desktop.exe'/s /v'/qn' 
        #Start-Process  -WindowStyle Hidden '.\Docker Desktop.exe'
        # $job = Start-Job -scriptblock {& 'C:\Program Files\Docker\Docker\Docker Desktop.exe'}
        $ErrorActionPreference = 'SilentlyContinue';
        do { $var1 = docker ps 2>$null } while (-Not $var1)
        $ErrorActionPreference = 'Stop';
        $myProcess = Get-Process 'Docker Desktop'
        $myProcess.CloseMainWindow() *>$null
        Write-Host "Docker Started Successfully"
        cd $og_path


    }
    else {
        Write-Host "Docker Already Running"
    }

    

    }
    else{
        Write-Host "Unable to initiate docker, kindly run docker manually"
        exit
    }

}

function wsl_conversion{

    Write-Host "`n-------------------------------------------" -ForegroundColor Green
    Write-Host "## Setting-up Environment to Deploy ##" -ForegroundColor Green
    Write-Host "-------------------------------------------`n" -ForegroundColor Green

    Write-Host("`nInitiating WSL 2 Conversion `n")

    $job = Start-Job {wsl --set-version Ubuntu 2}

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

    $job = Start-Job { wsl --install -d Ubuntu} | Out-Null

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


function load_images{

    ### Load docker images 

     wsl -u root -d Ubuntu bash -c "docker image ls --format 'table {{.Repository}}:{{.Tag}}'"

    ### Loading  Docker Images

    $x_image = (gci ((${pwd}.Path)+'\docker-images') | sort LastWriteTime | where {$_ -match 'x-docker' -and $_ -match '.tar'}).Name

    wsl -u root -d Ubuntu docker load -i ./docker-images/$x_image

    

    # $job = Start-Job {docker load -i $x_image}

    # Wait-Job $job

    # Receive-Job $job
  

    # docker ps --format "table {{.ID}}\t{{.Names}}"
    
    # $x = docker image ls --format "table {{.ID}}\t{{.Repository}}\t{{.Tag}}"

    # $x | where {$_ -match 'x'}

}



function install_choco{

    $ch = choco.exe -v
    
    # Getting Choco System Env
    $Choco_Install_Env = [System.Environment]::GetEnvironmentVariable('ChocolateyInstall','Machine')
    $Choco_Last_Update_Path = [System.Environment]::GetEnvironmentVariable('ChocolateyLastPathUpdate','User')

    # Getting Choco Path Entries for Machine and User Scopes
    $Choco_Path_System_ENV = ([System.Environment]::GetEnvironmentVariable("Path", "Machine")).split(";") | Where { $_ -match 'choco' }
    $Choco_Path_User_ENV = ([System.Environment]::GetEnvironmentVariable("Path", "User")).split(";") | Where { $_ -match 'choco' }

    if($ch)
    {

        Write-Host 'Chocolatey v'$ch' is installed already'    

    }
    else{
 
        $ChocoInstallDir = 'C:\ProgramData\chocoportable'
        $env:ChocolateyInstall = "$InstallDir"
 
        # If your PowerShell Execution policy is restrictive, you may
        # not be able to get around that. Try setting your session to
        # Bypass.

        Set-ExecutionPolicy Bypass -Scope Process -Force;
 
        # All install options - offline, proxy, etc at
        # https://chocolatey.org/install

        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
 
        $ch= choco.exe -v

        if($ch){
            
            Write-Host 'Chocolatey successfully installed'
         
        }
        else {
            
            Write-Host 'Chocolatey install failed try running the script with admin rights'
         
        }

    }

}

function packages{

    Write-Host "`n>> Adding Dependencies" -ForegroundColor Red
    wsl -u root -d Ubuntu bash -c "apt install -y p7zip-full "


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
    wsl -u root -d Ubuntu bash -c "k3d cluster create dev --agents 1 --wait --port 8443:8443@loadbalancer --k3s-arg --disable=traefik@server:0 `&`& sleep 17"
    
    #wsl -u root -d Ubuntu bash -c "k3d cluster create dev --agents 1 --wait --port 8080:8080@loadbalancer --port 6443:8443@loadbalancer --port 7080:80@loadbalancer --port 7443:443@loadbalancer --k3s-arg --disable=traefik@server:0 `&`& sleep 17"

}
# function init_cert_manager{

#     Write-Host "`n>> Deploying Cert-Manager" -ForegroundColor Red

#     wsl -u root -d Ubuntu bash -c "kubectl create ns cert-manager"

#     wsl -u root -d Ubuntu bash -c "helm repo add jetstack https://charts.jetstack.io `&`& helm repo update"

#     wsl -u root -d Ubuntu bash -c "kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.crds.yaml"

#     wsl -u root -d Ubuntu bash -c "helm install cert-manager jetstack/cert-manager --namespace cert-manager --wait --create-namespace --version v1.11.0 # --set installCRDs=true"

#     wsl -u root -d Ubuntu bash -c "kubectl wait --timeout=90s --for=condition=available deployment emissary-apiext -n cert-manager"

# wsl -u root -d Ubuntu bash -c "cat <<EOF | kubectl apply -f -
# ---
# apiVersion: cert-manager.io/v1
# kind: ClusterIssuer
# metadata:
#   name: selfsigned-issuer
#   namespace: cert-manager
# spec:
#   selfSigned: {}
# ---
# apiVersion: cert-manager.io/v1
# kind: Certificate
# metadata:
#   name: my-selfsigned-ca
#   namespace: cert-manager
# spec:
#   isCA: true
#   commonName: my-selfsigned-ca
#   secretName: root-secret
#   privateKey:
#     algorithm: ECDSA
#     size: 256
#   issuerRef:
#     name: selfsigned-issuer
#     kind: ClusterIssuer
#     group: cert-manager.io
# ---
# apiVersion: cert-manager.io/v1
# kind: Issuer
# metadata:
#   name: my-ca-issuer
#   namespace: cert-manager
# spec:
#   ca:
#     secretName: root-secret
# ---
# EOF"




# }

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
        CREATE DATABASE `"x`" WITH OWNER = `"postgres`" TABLESPACE = pg_default CONNECTION LIMIT = -1;
        CREATE DATABASE `"elasticsearch`" WITH OWNER = `"postgres`" TABLESPACE = pg_default CONNECTION LIMIT = -1;
        CREATE DATABASE `"keycloak`" WITH OWNER = `"postgres`" TABLESPACE = pg_default CONNECTION LIMIT = -1;
        CREATE DATABASE `"kafka`" WITH OWNER = `"postgres`" TABLESPACE = pg_default CONNECTION LIMIT = -1;
        CREATE DATABASE `"prometheus`" WITH OWNER = `"postgres`" TABLESPACE = pg_default CONNECTION LIMIT = -1;
        CREATE DATABASE `"argocd`" WITH OWNER = `"postgres`" TABLESPACE = pg_default CONNECTION LIMIT = -1;
        CREATE DATABASE `"webapp`" WITH OWNER = `"postgres`" TABLESPACE = pg_default CONNECTION LIMIT = -1;
---
EOF"

wsl -u root -d Ubuntu bash -c "cat <<EOF | helm upgrade pgadmin runix/pgadmin4 --version 1.13.6 --namespace appdb --install --set fullnameOverride=pgadmin -f -
persistentVolume:
  enabled: false
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

# function init_auth{

#     wsl -u root -d Ubuntu bash -c "kubectl delete ns auth"

# #     # wsl -u root -d Ubuntu bash -c "kubectl create namespace "

#     Write-Host "`n>> Deploying Keycloak" -ForegroundColor Red

#     # wsl -u root -d Ubuntu bash -c "kubectl create secret tls keycloak-tls --cert=/tmp/ssl/cert.crt --key=/tmp/ssl/cert.key -n auth"

# wsl -u root -d Ubuntu bash -c "cat <<EOF | helm upgrade auth bitnami/keycloak --namespace auth --create-namespace --install -f -
# global:
#   storageClass: `"local-path`"
# fullnameOverride: `"auth`"
# # namespaceOverride: `"auth`"
# production: false
# tls:
#   enabled: true
#   autoGenerated: true
# #   existingSecret: 'edge-stack-tls'
# # http:
# #   tlsSecret: <SecretName>
# livenessProbe:
#   enabled: false
# readinessProbe:
#   enabled: false
# auth:
#   adminUser: admin
#   adminPassword: `"admin`"
# proxy: none
# serviceAccount:
#   create: false
# httpRelativePath: `"/auth/`"
# service:
#   type: ClusterIP
#   http:
#     enabled: true
#   ports:
#     http: 8080
#     https: 8443
# # containerPorts:
# #   http: 8080
# #   https: 8443
# networkPolicy:
#   enabled: true
#   allowExternal: true
# postgresql:
#   enabled: false
# externalDatabase:
#   host: `"postgres.appdb`"
#   port: 5432
#   user: postgres
#   database: keycloak
#   password: `"postgres`"
# # hostname:
# #   hostname: localhost:8443
# #   admin: localhost:8443
# #   adminUrl: localhost:8443
# #   strict: false
# #   strictBackchannel: false
# args:
#   # - -Dkeycloak.migration.strategy=IGNORE_EXISTING
#   # - -b 0.0.0.0
#   # - -Dkeycloak.migration.action=import
#   # - -Dkeycloak.migration.provider=dir
#   # - -Dkeycloak.profile.feature.upload_scripts=enabled
#   # - -Dkeycloak.migration.dir=/opt/jboss/keycloak/import-dir
#   # - -Dkeycloak.migration.strategy=IGNORE_EXISTING
#   # - -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true
# extraEnvVars:
#   # - name: KC_HOSTNAME
#   #   value: 'localhost:8443'
#   # - name: KC_HOSTNAME_PORT
#   #   value: '80'
#   # - name: KC_HOSTNAME_PATH
#   #   value: '/auth'
#   - name: KC_HOSTNAME_URL
#     value: 'https://localhost:8443'
#   # - name: KC_HOSTNAME_ADMIN
#   #   value: 'localhost'
#   # - name: KC_HOSTNAME_ADMIN_URL
#   #   value: 'http://localhost:8443/auth'
#   - name: KC_HOSTNAME_STRICT
#     value: 'false'
#   - name: KC_HOSTNAME_STRICT_BACKCHANNEL
#     value: 'false'
#   - name: KC_HOSTNAME_STRICT_HTTPS
#     value: 'false'
#   # - name: KC_HTTP_HOST
#   #   value: '0.0.0.0'
#   # - name: KC_HTTP_PORT
#   #   value: '8080'
#   # - name: KC_HTTPS_PORT
#   #   value: '8443'
# ---
# EOF"
# wsl -u root -d Ubuntu bash -c "kubectl delete mappings auth-map -n auth"
# wsl -u root -d Ubuntu bash -c "kubectl delete mappings auth-map -n auth"
# wsl -u root -d Ubuntu bash -c "kubectl delete mappings auth-login -n auth"
# wsl -u root -d Ubuntu bash -c "kubectl delete mappings auth2-login -n auth"

# # wsl -u root -d Ubuntu bash -c "cat <<EOF | kubectl apply -f -
# # ---
# # apiVersion: getambassador.io/v2
# # kind:  Mapping
# # metadata:
# #   name:  auth-map
# #   namespace: auth
# # spec:
# #   prefix: /auth
# #   rewrite: /auth
# #   service: auth:8080
# #   host: localhost:8443
# #   bypass_auth: true
# # ---
# # EOF"

# # wsl -u root -d Ubuntu bash -c "cat <<EOF | kubectl apply -f -
# # ---
# # apiVersion: getambassador.io/v3alpha1
# # kind:  Mapping
# # metadata:
# #   name:  auth-login
# #   namespace: auth
# # spec:
# #   prefix: /auth/admin/
# #   service: auth:8080
# #   host: localhost:8443
# #   regex_headers:
# #     x-auth-login: '.*'
# # ---
# # apiVersion: getambassador.io/v3alpha1
# # kind:  Mapping
# # metadata:
# #   name:  auth-map
# #   namespace: auth
# # spec:
# #   prefix: /auth
# #   rewrite: /auth
# #   service: auth:8080
# #   host: localhost:8443
# # ---
# # EOF"

# # ---
# # apiVersion: getambassador.io/v2
# # kind:  Mapping
# # metadata:
# #   name: auth-map
# # spec:
# #   prefix: /auth
# #   rewrite: /auth
# #   service: auth:443
# #   host: localhost:8443
# #   add_request_headers:
# #     X-Script-Name: /auth/
# #     X-Forwarded-Proto: https
# #   bypass_auth: true
# # ---
# # EOF"

# # wsl -u root -d Ubuntu bash -c "cat <<EOF | kubectl apply -n auth -f -
# # ---
# # apiVersion: getambassador.io/v2
# # kind:  Mapping
# # metadata:
# #   name:  auth2-login
# # spec:
# #   prefix: /auth/admin/master/console/
# #   rewrite: /auth/admin/master/console/
# #   service: auth:8080
# #   host: localhost:8443
# #   add_request_headers:
# #     X-Script-Name: /auth/admin/master/console/
# #     X-Forwarded-Proto: https
# #   add_response_headers:
# #     location:
# #       append: False
# #       value: https://localhost:8443/auth/admin/master/console/
# #   bypass_auth: true
# # ---
# # apiVersion: getambassador.io/v2
# # kind:  Mapping
# # metadata:
# #   name:  auth-login
# # spec:
# #   prefix: /auth/admin/
# #   rewrite: /auth/admin/
# #   service: auth:8080
# #   host: localhost:8443
# #   add_request_headers:
# #     X-Script-Name: /auth/admin
# #     X-Forwarded-Proto: https
# #   add_response_headers:
# #     location:
# #       append: False
# #       value: https://localhost:8443/auth/admin
# #   bypass_auth: true
# # ---
# # apiVersion: getambassador.io/v2
# # kind:  Mapping
# # metadata:
# #   name: auth-map
# # spec:
# #   prefix: /auth
# #   rewrite: /auth/
# #   service: auth:8080
# #   host: localhost:8443
# #   add_request_headers:
# #     X-Script-Name: /auth/
# #     X-Forwarded-Proto: https
# #   bypass_auth: true
# # ---
# # EOF"

# wsl -u root -d Ubuntu bash -c "cat <<EOF | kubectl apply -n auth -f -
# ---
# apiVersion: getambassador.io/v2
# kind: Mapping
# metadata:
#   name: auth-map
#   namespace: auth
# spec:
#   add_request_headers:
#     x-forwarded-uri: https://%REQ(:authority)%%REQ(:path)%
#   add_response_headers:
#     Access-Control-Allow-Origin: localhost:8443
#     Content-Security-Policy: 'connect-src https://localhost:8443/ blob:; default-src
#       blob: data: ''self''; img-src blob: data: ''self''; script-src ''self'' ''sha256-wSk7Pac68P5NGz0ckYIUSA8nd7eh8zkveKcseL24KB0='';
#       style-src ''self'' ''unsafe-inline'';'
#     Strict-Transport-Security: max-age=315360000; includeSubDomains; preload
#     X-Content-Type-Options: nosniff
#     X-Frame-Options: sameorigin
#     X-XSS-Protection: 1; mode=block
#   connect_timeout_ms: 4000
#   host: localhost:8443
#   idle_timeout_ms: 500000
#   prefix: /auth
#   rewrite: /auth
#   service: auth:8080
#   timeout_ms: 75000
# ---
# EOF"

# }

function init_pv{

wsl -u root -d Ubuntu bash -c "cat <<EOF | kubectl apply -f -
---
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: x-pv-claim-dev
  namespace: x
spec:
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 1000M
  storageClassName: local-path

---
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: tci-testing-pv-claim
  namespace: x
spec:
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 1Gi
  storageClassName: local-path

---
EOF"

}
function init_x{

Write-Host "`n>> Deploying X" -ForegroundColor Red

wsl -u root -d Ubuntu bash -c "cp ./charts/x.tgz /tmp"

wsl -u root -d Ubuntu bash -c "cat <<EOF | helm upgrade x /tmp/x.tgz -n x --create-namespace --wait --install -f -
namespace: x
fullnameOverride: `"x`"
storageClass: `"local-path`"
service:
  type: ClusterIP
  port: 8080
x:
  admin:
    group: `"xadmin`"
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


function test_deploy_nginx{

    kubectl create deploy nginx --image nginx -n x

    kubectl expose deploy/nginx --type=ClusterIP --port=80 --name=nginxcip -n x
 
    Start-Process -FilePath "C:\Program Files\Google\Chrome\Application\chrome.exe" -ArgumentList '--start-fullscreen -new-window "http://localhost"'
}

function stop_cluster{
    wsl -u root -d Ubuntu bash -c "k3d cluster stop dev"

}

function start_cluster{
    wsl -u root -d Ubuntu bash -c "k3d cluster start dev"

}
function auto{

    wsl_checks
    initialize_ubuntu
    install_docker_wsl
    packages
    install_k3d
    install_helm
    install_kubectl
    initialize_k3d
    initialize_k8s_infra
    deploying_volumes




}

function init_dev{

    wsl_checks
    initialize_ubuntu
    install_docker_wsl
    packages
    install_k3d
    install_helm
    install_kubectl
    initialize_k3d
    init_edge_stack
    init_cert_manager




}
function init_app{

    remove_k3d
    initialize_k3d
    init_edge_stack
    init_db_charts
    # init_auth
    k3d_image_import
    init_x
    init_x_view




}
function remove_k3d{

    Write-Host "`n>> Deleting k3d dev Cluster" -ForegroundColor Red
    wsl -u root -d Ubuntu bash -c "k3d cluster delete dev"

}

function k3d_image_import{

    Write-Host "`n>> Importing Images" -ForegroundColor Red
    wsl -u root -d Ubuntu bash -c "pwd"
    wsl -u root -d Ubuntu bash -c "k3d image import ./docker-images/x-docker-image.tar -c dev"
    wsl -u root -d Ubuntu bash -c "k3d image import ./docker-images/x-view-docker-image.tar -c dev"
}



function filters{

wsl -u root -d Ubuntu bash -c "kubectl delete filter filter -n ambassador"
wsl -u root -d Ubuntu bash -c "kubectl delete filterpolicy quote-policy -n quote"

wsl -u root -d Ubuntu bash -c "cat <<EOF | kubectl apply -f -
---
apiVersion: getambassador.io/v3alpha1
kind: Filter
metadata:
  name: filter
  namespace: ambassador
spec:
  OAuth2:
    authorizationURL: http://localhost:8080/auth/realms/test
    grantType: `"AuthorizationCode`"
    audience: test
    lifetime: `"1m`"
    clientSessionMaxIdle: `"1m`"
    expirationSafetyMargin: `"1m`"
    clientID: test
    secret: OAxd1HHTygtDT3GWVGEEyhOaWR89VW1l
    protectedOrigins:
    - origin: http://localhost:8080
---
apiVersion: getambassador.io/v3alpha1
kind: FilterPolicy
metadata:
  name: quote-policy
  namespace: quote
spec:
  rules:
    - host: `"localhost:8080`"
      path: /backend
      filters:
        - name: filter
          namespace: ambassador
        #   arguments:
        #     scope:
        #     - `"test_scope`"
---
EOF"



}


function install_cert{
    Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match 'localhost' -and $_.Issuer -match 'localhost' } | Remove-Item
    Import-Certificate -FilePath (${pwd}.Path+"\ssl\cert.crt") -CertStoreLocation Cert:\LocalMachine\Root

}
## Execution Block
if ($param -eq "--pre"){ pre_pre }
elseif ($param -eq "--edit-env"){ edit_env }
elseif ($param -eq "--sys-check"){ logo; sys_check }
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
elseif ($param -eq "--init-dev"){ init_dev }
elseif ($param -eq "--init-edge-stack"){ init_edge_stack }
elseif ($param -eq "--init-cert-manager"){ init_cert_manager }
elseif ($param -eq "--init-app"){ init_app }
elseif ($param -eq "--init-auth"){ init_auth }
elseif ($param -eq "--init-x"){ init_x }
elseif ($param -eq "--init-x-view"){ init_x_view }
elseif ($param -eq "--init-pv"){ init_pv }
elseif ($param -eq "--filter"){ filters }
elseif ($param -eq "--install-cert"){ install_cert }
#################################################
elseif ($param -eq "--flush-deploy"){ del_deploy }
elseif ($param -eq "--flush-k3d"){ remove_k3d }
elseif ($param -eq "--flush-services"){ remove_services }
elseif ($param -eq "--flush-ubuntu"){ clear_ubuntu }
elseif ($param -eq "--flush-docker-wsl"){ flush_docker_wsl }
#################################################
elseif ($param -eq "--load-docker-images"){ load_images }
elseif ($param -eq "--load-k3d-images"){ k3d_image_import }
elseif ($param -eq "--complete"){ complete }

else {
    Write-Host ("`nHelp")
    Write-Host ("#####")
    Write-Host ("`nAdd the following parameters along when executing the script to get the appropriate outcome")
    Write-Host ("'--init-wsl'       -- For Initializing Ubuntu-22.04 Setup.")
    Write-Host ("'--auto-deploy'    -- For automatic deployment.")
    Write-Host ("'--flush-deploy'   -- For deleting the complete deployment.")
    Write-Host ("'--sys-check'      -- For checking sytem requirements check.")
    Write-Host ("'--update'         -- For updating zenith services on existing deployment.`n")
}



