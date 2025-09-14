import pytest
import requests
import json
import os
import time
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import threading
# import shlex

BASE_URL = "http://localhost:5001"
TEST_USER = "benchmark_user@example.com"
TEST_PASSWORD = "BenchmarkPassword123"
TOKEN_FILE = "test/stress_token.json"
LOG_FILE = "test/stress_test_log.csv"
TARGET_FOLDER = r"E:\TARP\testupload" # This folder should contain files for testing

class DockerStatsMonitor:
    def __init__(self, container_name_prefixes, interval=1):
        self.container_name_prefixes = container_name_prefixes if isinstance(container_name_prefixes, list) else [container_name_prefixes]
        self.interval = interval
        self.stats_data = {prefix: [] for prefix in self.container_name_prefixes}
        self._stop_event = threading.Event()
        self._thread = None
        self.container_ids = {}

    def _get_container_ids(self):
        for prefix in self.container_name_prefixes:
            try:
                cmd = f'docker ps -qf "name={prefix}"'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
                container_ids = result.stdout.strip().split('\n')
                if container_ids and container_ids[0]:
                    self.container_ids[prefix] = container_ids[0]
                    print(f"Found container ID for {prefix}: {self.container_ids[prefix]}")
                else:
                    print(f"Container with name prefix '{prefix}' not found.")
            except subprocess.CalledProcessError as e:
                print(f"Error getting container ID for {prefix}: {e}")
                self.container_ids[prefix] = None

    def _monitor_loop(self):
        self._get_container_ids()
        if not self.container_ids:
            print("Cannot start Docker stats monitoring: No container IDs found.")
            return

        while not self._stop_event.is_set():
            for prefix, container_id in self.container_ids.items():
                if not container_id:
                    continue
                try:
                    cmd = [
                        'docker', 'stats', container_id, '--no-stream',
                        '--format', '{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}}'
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                    output = result.stdout.strip()
                    if output:
                        timestamp = datetime.now().isoformat()
                        cpu_perc, mem_usage, mem_perc, net_io = output.split(',')
                        self.stats_data[prefix].append({
                            "timestamp": timestamp,
                            "cpu_perc": cpu_perc.strip(),
                            "mem_usage": mem_usage.strip(),
                            "mem_perc": mem_perc.strip(),
                            "net_io": net_io.strip()
                        })
                except subprocess.CalledProcessError as e:
                    print(f"Error collecting docker stats for {prefix}: {e}")
                except Exception as e:
                    print(f"An unexpected error occurred in monitor loop for {prefix}: {e}")
            
            self._stop_event.wait(self.interval)

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._monitor_loop)
            self._thread.daemon = True
            self._thread.start()
            print("DockerStatsMonitor started.")

    def stop(self):
        if self._thread is not None:
            self._stop_event.set()
            self._thread.join()
            print("DockerStatsMonitor stopped.")

    def get_stats_in_range(self, start_time, end_time):
        # Filter stats collected within the given time range for all containers
        # start_time and end_time are datetime objects
        result = {}
        for prefix, data_list in self.stats_data.items():
            result[prefix] = [
                s for s in data_list 
                if datetime.fromisoformat(s["timestamp"]) >= start_time and 
                   datetime.fromisoformat(s["timestamp"]) <= end_time
            ]
        return result

# Helper function to log operations to CSV
def log_operation_to_csv(log_file, data):
    file_exists = os.path.isfile(log_file)
    with open(log_file, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

@pytest.fixture(scope="session")
def jwt_token_stress():
    """Fixture to get or generate a JWT token for stress testing."""
    # Always register and login to get a fresh token for each test run
    print(f"DEBUG: Registering and logging in new user to get a fresh token.")
    register_url = f"{BASE_URL}/api/v1/auth/register"
    register_payload = {"email": TEST_USER, "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD}
    requests.post(register_url, json=register_payload)

    login_url = f"{BASE_URL}/api/v1/auth/login"
    login_payload = {"email": TEST_USER, "password": TEST_PASSWORD}
    response = requests.post(login_url, json=login_payload)
    response.raise_for_status()
    login_data = response.json()
    access_token = login_data["tokens"]["access_token"]
    refresh_token = login_data["tokens"]["refresh_token"]
    user_id = login_data["user"]["id"]
    with open(TOKEN_FILE, "w") as f:
        json.dump({"access_token": access_token, "refresh_token": refresh_token, "user_id": user_id}, f)
    return access_token, refresh_token, user_id

@pytest.fixture(scope="module")
def dummy_stress_files(tmp_path_factory):
    """Fixture to create dummy files for stress testing."""
    # Create a temporary directory for test files
    test_files_dir = tmp_path_factory.mktemp(TARGET_FOLDER)
    
    # Create a few files of different sizes
    file_sizes = [10 * 1024, 100 * 1024, 1024 * 1024] # 10KB, 100KB, 1MB
    file_paths = []
    for i, size in enumerate(file_sizes):
        file_path = test_files_dir / f"dummy_file_{i}.bin"
        with open(file_path, "wb") as f:
            f.write(os.urandom(size)) # Write random bytes
        file_paths.append(file_path)
    return file_paths

def upload_file_stress(access_token, file_path):
    print(f"DEBUG: upload_file_stress received token: {access_token[:30]}...")
    headers = {"Authorization": f"Bearer {access_token}"}
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'), 'application/octet-stream')}
    response = requests.post(f"{BASE_URL}/api/v1/files/upload", headers=headers, files=files)
    response.raise_for_status()
    return response.json()["file"]["file_id"]

def create_download_token_stress(access_token, file_id):
    headers = {"Authorization": f"Bearer {access_token}"}
    token_response = requests.post(f"{BASE_URL}/api/v1/files/{file_id}/token", headers=headers, json={"ttl_seconds": 60})
    token_response.raise_for_status()
    return token_response.json()["token"]

def download_file_stress(download_url):
    response = requests.get(download_url, stream=True)
    response.raise_for_status()
    for chunk in response.iter_content(chunk_size=8192):
        pass # Consume the content to simulate a full download

def delete_file_stress(access_token, file_id):
    headers = {"Authorization": f"Bearer {access_token}"}
    delete_url = f"{BASE_URL}/api/v1/files/{file_id}"
    response = requests.delete(delete_url, headers=headers)
    response.raise_for_status()

def get_files_in_folder(folder_path):
    """Recursively get all file paths and their sizes in a given folder."""
    file_details = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                file_size = os.path.getsize(file_path)
                file_details.append({"path": file_path, "size": file_size})
            except OSError as e:
                print(f"Error getting size for {file_path}: {e}")
    # Sort by file size (smallest to largest)
    file_details.sort(key=lambda x: x["size"])
    return file_details

@pytest.fixture(scope="module")
def stress_files_to_process():
    """Fixture to get all files from TARGET_FOLDER, sorted by size."""
    if not os.path.exists(TARGET_FOLDER):
        os.makedirs(TARGET_FOLDER, exist_ok=True)
        print(f"Created TARGET_FOLDER: {TARGET_FOLDER}. Please add files to this folder for testing.")
        return []
    
    files = get_files_in_folder(TARGET_FOLDER)
    if not files:
        print(f"No files found in {TARGET_FOLDER}. Please add files for testing.")
    return files

@pytest.mark.parametrize("iteration", range(1)) # Run the full cycle once for now
def test_end_to_end_file_operations_stress(jwt_token_stress, stress_files_to_process, iteration):
    print(f"DEBUG: Entering test_end_to_end_file_operations_stress for iteration {iteration}")
    access_token, _, _ = jwt_token_stress
    print(f"DEBUG: Using access token: {access_token[:30]}...") # Print first 30 chars of token
    uploaded_file_ids = []
    uploaded_file_info = [] # To store file_id, original_path, file_type, folder_path

    if not stress_files_to_process:
        pytest.skip(f"No files to process in {TARGET_FOLDER}. Skipping stress test.")

    # Initialize Docker Stats Monitor for multiple containers
    monitor = DockerStatsMonitor(container_name_prefixes=["qss4-backend-test", "postgres-test", "redis-test"], interval=0.5) # Collect stats every 0.5 seconds
    monitor.start()
    time.sleep(1) # Give monitor a moment to start collecting

    try:
        def run_all_operations():
            # --- Upload Phase ---
            print(f"Iteration {iteration}: Starting upload phase...")
            for file_detail in stress_files_to_process:
                result = _perform_upload_and_log(access_token, file_detail, monitor)
                if result:
                    uploaded_file_ids.append(result["file_id"])
                    uploaded_file_info.append(result)
            print(f"DEBUG: Upload phase finished. {len(uploaded_file_info)} files uploaded.")

            # --- Download Phase ---
            print(f"Iteration {iteration}: Starting download phase...")
            for file_info in uploaded_file_info:
                _perform_download_and_log(access_token, file_info, monitor)

            # --- Delete Phase ---
            print(f"Iteration {iteration}: Starting delete phase...")
            for file_info in uploaded_file_info:
                _perform_delete_and_log(access_token, file_info, monitor)

        # benchmark(run_all_operations)
        run_all_operations()

    finally:
        monitor.stop()
        print("End-to-end stress test completed.")

def _perform_upload_and_log(access_token, file_detail, monitor):
    print(f"DEBUG: Starting upload for {file_detail['path']}")
    file_path = file_detail["path"]
    file_size = file_detail["size"]
    file_name = os.path.basename(file_path)
    file_extension = os.path.splitext(file_name)[1]
    relative_folder_path = os.path.relpath(os.path.dirname(file_path), TARGET_FOLDER)
    if relative_folder_path == '.':
        relative_folder_path = '/'

    start_time = datetime.now()
    file_id = upload_file_stress(access_token, file_path)
    end_time = datetime.now()
    duration_ms = (end_time - start_time).total_seconds() * 1000

    # Get Docker stats for this operation for all monitored containers
    stats_in_range = monitor.get_stats_in_range(start_time, end_time)
    log_data = {
        "timestamp": start_time.isoformat(),
        "operation_type": "upload",
        "filename": file_name,
        "file_extension": file_extension,
        "folder_path": relative_folder_path,
        "file_size_bytes": file_size,
        "file_id": file_id,
        "status": "success",
        "duration_ms": duration_ms,
    }
    for prefix, stats_list in stats_in_range.items():
        avg_cpu = sum([float(s["cpu_perc"].replace('%', '')) for s in stats_list]) / len(stats_list) if stats_list else 0
        avg_mem_perc = sum([float(s["mem_perc"].replace('%', '')) for s in stats_list]) / len(stats_list) if stats_list else 0
        # Extract NetIO from the last stat entry in the range, as it's cumulative
        net_io = stats_list[-1]["net_io"] if stats_list and "net_io" in stats_list[-1] else "0B / 0B"
        log_data[f"avg_cpu_perc_{prefix}"] = f"{avg_cpu:.2f}%"
        log_data[f"avg_mem_perc_{prefix}"] = f"{avg_mem_perc:.2f}%"
        log_data[f"net_io_{prefix}"] = net_io
    log_operation_to_csv(LOG_FILE, log_data)
    print(f"Uploaded {file_name} (ID: {file_id}) in {duration_ms:.2f}ms.")
    print(f"DEBUG: Finished upload for {file_detail['path']}")
    return {
        "file_id": file_id,
        "original_path": file_path,
        "file_name": file_name,
        "file_extension": file_extension,
        "folder_path": relative_folder_path,
        "file_size": file_size
    }

def _perform_download_and_log(access_token, file_info, monitor):
    print(f"DEBUG: Starting download for {file_info['file_name']}")
    file_id = file_info["file_id"]
    file_name = file_info["file_name"]
    file_extension = file_info["file_extension"]
    relative_folder_path = file_info["folder_path"]
    file_size = file_info["file_size"]

    # Create token
    start_token_time = datetime.now()
    download_token = create_download_token_stress(access_token, file_id)
    end_token_time = datetime.now()
    token_duration_ms = (end_token_time - start_token_time).total_seconds() * 1000
    download_url = f"{BASE_URL}/api/v1/files/{file_id}/download?token={download_token}"

    # Get Docker stats for token creation
    stats_in_range_token = monitor.get_stats_in_range(start_token_time, end_token_time)
    log_data_token = {
        "timestamp": start_token_time.isoformat(),
        "operation_type": "create_download_token",
        "filename": file_name,
        "file_extension": file_extension,
        "folder_path": relative_folder_path,
        "file_size_bytes": file_size,
        "file_id": file_id,
        "status": "success",
        "duration_ms": token_duration_ms,
    }
    for prefix, stats_list in stats_in_range_token.items():
        avg_cpu = sum([float(s["cpu_perc"].replace('%', '')) for s in stats_list]) / len(stats_list) if stats_list else 0
        avg_mem_perc = sum([float(s["mem_perc"].replace('%', '')) for s in stats_list]) / len(stats_list) if stats_list else 0
        net_io = stats_list[-1]["net_io"] if stats_list and "net_io" in stats_list[-1] else "0B / 0B"
        log_data_token[f"avg_cpu_perc_{prefix}"] = f"{avg_cpu:.2f}%"
        log_data_token[f"avg_mem_perc_{prefix}"] = f"{avg_mem_perc:.2f}%"
        log_data_token[f"net_io_{prefix}"] = net_io
    log_operation_to_csv(LOG_FILE, log_data_token)

    # Download file
    start_download_time = datetime.now()
    download_file_stress(download_url)
    end_download_time = datetime.now()
    download_duration_ms = (end_download_time - start_download_time).total_seconds() * 1000

    # Get Docker stats for download
    stats_in_range_download = monitor.get_stats_in_range(start_download_time, end_download_time)
    log_data_download = {
        "timestamp": start_download_time.isoformat(),
        "operation_type": "download",
        "filename": file_name,
        "file_extension": file_extension,
        "folder_path": relative_folder_path,
        "file_size_bytes": file_size,
        "file_id": file_id,
        "status": "success",
        "duration_ms": download_duration_ms,
    }
    for prefix, stats_list in stats_in_range_download.items():
        avg_cpu = sum([float(s["cpu_perc"].replace('%', '')) for s in stats_list]) / len(stats_list) if stats_list else 0
        avg_mem_perc = sum([float(s["mem_perc"].replace('%', '')) for s in stats_list]) / len(stats_list) if stats_list else 0
        net_io = stats_list[-1]["net_io"] if stats_list and "net_io" in stats_list[-1] else "0B / 0B"
        log_data_download[f"avg_cpu_perc_{prefix}"] = f"{avg_cpu:.2f}%"
        log_data_download[f"avg_mem_perc_{prefix}"] = f"{avg_mem_perc:.2f}%"
        log_data_download[f"net_io_{prefix}"] = net_io
    log_operation_to_csv(LOG_FILE, log_data_download)
    print(f"Downloaded file {file_name} (ID: {file_id}) in {download_duration_ms:.2f}ms.")
    print(f"DEBUG: Finished download for {file_info['file_name']}")

def _perform_delete_and_log(access_token, file_info, monitor):
    print(f"DEBUG: Starting delete for {file_info['file_name']}")
    file_id = file_info["file_id"]
    file_name = file_info["file_name"]
    file_extension = file_info["file_extension"]
    relative_folder_path = file_info["folder_path"]
    file_size = file_info["file_size"]

    start_time = datetime.now()
    delete_file_stress(access_token, file_id)
    end_time = datetime.now()
    duration_ms = (end_time - start_time).total_seconds() * 1000

    # Get Docker stats for this operation for all monitored containers
    stats_in_range = monitor.get_stats_in_range(start_time, end_time)
    log_data = {
        "timestamp": start_time.isoformat(),
        "operation_type": "delete",
        "filename": file_name,
        "file_extension": file_extension,
        "folder_path": relative_folder_path,
        "file_size_bytes": file_size,
        "file_id": file_id,
        "status": "success",
        "duration_ms": duration_ms,
    }
    for prefix, stats_list in stats_in_range.items():
        avg_cpu = sum([float(s["cpu_perc"].replace('%', '')) for s in stats_list]) / len(stats_list) if stats_list else 0
        avg_mem_perc = sum([float(s["mem_perc"].replace('%', '')) for s in stats_list]) / len(stats_list) if stats_list else 0
        net_io = stats_list[-1]["net_io"] if stats_list and "net_io" in stats_list[-1] else "0B / 0B"
        log_data[f"avg_cpu_perc_{prefix}"] = f"{avg_cpu:.2f}%"
        log_data[f"avg_mem_perc_{prefix}"] = f"{avg_mem_perc:.2f}%"
        log_data[f"net_io_{prefix}"] = net_io
    log_operation_to_csv(LOG_FILE, log_data)
    print(f"Deleted file {file_name} (ID: {file_id}) in {duration_ms:.2f}ms.")
    print(f"DEBUG: Finished delete for {file_info['file_name']}")