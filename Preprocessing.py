import os
import subprocess
import time
import pandas as pd
# Paths
procmon_path = r"C:\Users\monso\OneDrive\Desktop\Repos\Ransomware_detection\Process_Monitor\Procmon64.exe"
log_file_path = r"C:\Users\monso\OneDrive\Desktop\Repos\Ransomware_detection\Process_Monitor\procmon_log.pml"
csv_file_path = r"C:\Users\monso\OneDrive\Desktop\Repos\Ransomware_detection\data_csv\procmon_log.csv"

# Function to start Process Monitor
def start_procmon():
    # Command to start Process Monitor with a log file
    command = [
        procmon_path,
        "/Quiet",            # Run in quiet mode
        "/Minimized",        # Start minimized
        "/Backingfile", log_file_path,  # Path to save the log file
    ]
    subprocess.Popen(command)

# Function to stop Process Monitor
def stop_procmon():
    command = [procmon_path, "/Terminate"]
    subprocess.run(command)

# Function to convert .pml to .csv
def convert_pml_to_csv():
    command = [procmon_path, "/OpenLog", log_file_path, "/SaveAs", csv_file_path]
    subprocess.run(command)
    print(f"Process Monitor log converted to CSV and saved to {csv_file_path}")

# Start Process Monitor
start_procmon()

# Capture data for a specific duration (e.g., 10 seconds)
time.sleep(10)  # Adjust the duration as needed

# Stop Process Monitor
stop_procmon()

# Convert .pml log file to CSV
convert_pml_to_csv()

# Function to remove rows with "Procmon64.exe" and keep specified features
def clean_csv(input_csv_path, output_csv_path):
    # Load the CSV file
    df = pd.read_csv(input_csv_path)
    
    # Specify the features to keep
    features_to_keep = [
        'Time of Day', 'Process Name', 'PID', 'Operation', 'Path', 'Result', 'Detail', 
        'process_path', 'tree_process_name', 'api', 'command_line', 'tree_command_line', 'apistats', 'errors', 'description', 'info'
    ]

    # Ensure only the specified features are kept and remove rows where Process Name is "Procmon64.exe"
    filtered_df = df[~df['Process Name'].str.lower().str.contains('procmon64.exe')]
    filtered_df = filtered_df[features_to_keep]

    # Save the cleaned dataset to a new CSV file
    filtered_df.to_csv(output_csv_path, index=False)
    print(f"Cleaned CSV file saved as {output_csv_path}")

# Path to save the cleaned CSV file
cleaned_csv_file_path = r"C:\Users\monso\OneDrive\Desktop\Repos\Ransomware_detection\data_csv\procmon_log_cleaned.csv"

# Clean the CSV file to remove rows with "Procmon64.exe" and keep specified features
clean_csv(csv_file_path, cleaned_csv_file_path)
