import tkinter as tk
from tkinter import messagebox
import subprocess
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import time

# Paths
procmon_path = r"C:\Users\monso\OneDrive\Desktop\Repos\Ransomware_detection\Process_Monitor\Procmon64.exe"
procmon_log_path = r"C:\Users\monso\OneDrive\Desktop\Repos\Ransomware_detection\Process_Monitor\procmon_log.pml"
csv_log_path = r"C:\Users\monso\OneDrive\Desktop\Repos\Ransomware_detection\data_csv\procmon_log.csv"
preprocessed_log_path = r"C:\Users\monso\OneDrive\Desktop\Repos\Ransomware_detection\data_csv\preprocessed_procmon_log.csv"
model_path = r"C:\Users\monso\OneDrive\Desktop\Repos\Ransomware_detection\models\gradient_boosting_modelli.h5"
sample_csv_path = r"C:\Users\monso\OneDrive\Desktop\Repos\Ransomware_detection\data_csv\sample.csv"

# Function to start procmon.exe, process the log, and preprocess it
def monitor():
    # Start procmon.exe to capture system calls
    def start_procmon():
        # Command to start Process Monitor with a log file
        command = [
            procmon_path,
            "/Quiet",            # Run in quiet mode
            "/Minimized",        # Start minimized
            "/Backingfile", procmon_log_path,  # Path to save the log file
        ]
        subprocess.Popen(command)

    # Function to stop Process Monitor
    def stop_procmon():
        command = [procmon_path, "/Terminate"]
        subprocess.run(command)

    # Function to convert .pml to .csv
    def convert_pml_to_csv():
        command = [procmon_path, "/OpenLog", procmon_log_path, "/SaveAs", csv_log_path]
        subprocess.run(command)
        print(f"Process Monitor log converted to CSV and saved to {csv_log_path}")

    # Start Process Monitor
    start_procmon()

    # Capture data for a specific duration (e.g., 10 seconds)
    time.sleep(20)  # Adjust the duration as needed

    # Stop Process Monitor
    stop_procmon()

    # Convert .pml log file to CSV
    convert_pml_to_csv()

    # Load the CSV file
    data = pd.read_csv(csv_log_path)
        
    # Preprocess the features
    makerr(data)
    
    # Show a message that analysis is complete
    messagebox.showinfo("Monitor", "Analysis complete. You can now detect.")

# Function to preprocess the features
def makerr(data):
    # Group by process name and aggregate data
    def aggregate_features(group):
        features = {
            'file_created': (group['Operation'] == 'CreateFile').sum(),
            'file_read': (group['Operation'] == 'ReadFile').sum(),
            'urls': (group['Operation'].isin(['TCP Connect', 'UDP Send'])).sum(),
            'apistats': (group['Operation'].str.contains('API')).sum(),
            'dll_loaded': (group['Operation'] == 'Load Image').sum(),
            'directory_enumerated': (group['Operation'] == 'QueryDirectory').sum(),
            'action': (group['Operation'].isin(['WriteFile', 'RegSetValue'])).any(),
            'proc_pid': group['PID'].nunique(),
            'tcp': (group['Operation'] == 'TCP Connect').sum(),
            'udp': (group['Operation'] == 'UDP Send').sum(),
            'regkey_read': (group['Operation'] == 'RegQueryValue').sum(),
            'wmi_query': (group['Operation'] == 'WmiQuery').sum(),
            'regkey_written': (group['Operation'] == 'RegSetValue').sum(),
        }
        return pd.Series(features)

    # Apply the aggregation function to the grouped data
    aggregated_process_df = data.groupby('Process Name').apply(aggregate_features).reset_index()

    # Save the aggregated data to a CSV file
    aggregated_process_df.to_csv(preprocessed_log_path, index=False)
    print(f"Preprocessed CSV file saved as {preprocessed_log_path}")
    print("Columns after preprocessing:", aggregated_process_df.columns.tolist())
    print("Sample data after preprocessing:\n", aggregated_process_df.head())

# Function to classify ransomware families based on feature values
def classify_ransomware_family(features):
    if features['file_created'] > 100 and features['file_read'] > 100:
        return 'Trojan'
    elif features['urls'] > 20:
        return 'Worm'
    elif features['apistats'] > 30:
        return 'Spyware'
    elif features['dll_loaded'] > 20:
        return 'Adware'
    elif features['directory_enumerated'] > 20:
        return 'Ransomware (Locker)'
    elif features['regkey_written'] > 20:
        return 'Ransomware (Encrypter)'
    elif features['wmi_query'] > 20:
        return 'Rootkit'
    elif features['action'] > 20:
        return 'Keylogger'
    elif features['tcp'] > 20:
        return 'Worm'
    elif features['udp'] > 20:
        return 'Worm'
    elif features['regkey_read'] > 20:
        return 'Spyware'
    elif features['wmi_query'] > 20:
        return 'Rootkit'
    elif features['regkey_written'] > 20:
        return 'Ransomware (Encrypter)'
    else:
        return 'Unknown'
    

# Function to load the model and detect G, L, and E cases
def detect():
    # Load the preprocessed data
    data = pd.read_csv(preprocessed_log_path)
    
    # Separate the process names from the features
    process_names = data['Process Name']
    features = data.drop(columns=['Process Name'])
    
    # Load the trained model
    model_dict = joblib.load(model_path)
    
    # Extract the actual model from the dictionary
    model = model_dict["model"]
    
    # Print the columns of the preprocessed data for debugging
    print("Columns in the preprocessed data:", features.columns.tolist())
    
    # Make predictions
    predictions = model.predict(features)
    
    # Print the actual predictions for debugging
    print("Predictions:", predictions)
    
    # Map predictions to descriptive labels
    label_mapping = {1: 'Goodware', 2: 'Locker Ransomware', 0: 'Encrypter Ransomware'}  # Adjust based on your label encoding
    prediction_labels = pd.Series(predictions).map(label_mapping)
    
    # Count the predictions for each class
    prediction_counts = prediction_labels.value_counts(normalize=True) * 100
    prediction_counts = prediction_counts.round(2)
    
    # Display the results as percentages
    result_message = "\n".join([f"{label}: {count}%" for label, count in prediction_counts.items()])
    result_label.config(text=result_message)

    # Print the prediction counts for debugging
    print("Prediction Counts:", prediction_counts)

    # Update the system call log display
    encrypter_processes = process_names[prediction_labels == 'Encrypter Ransomware'].tolist()
    locker_processes = process_names[prediction_labels == 'Locker Ransomware'].tolist()
    
    encrypter_text.delete(1.0, tk.END)
    for process_name in encrypter_processes:
        process_features = data[data['Process Name'] == process_name].iloc[0]
        family = classify_ransomware_family(process_features)
        encrypter_text.insert(tk.END, f"{process_name} - {family}\n")
    
    locker_text.delete(1.0, tk.END)
    for process_name in locker_processes:
        process_features = data[data['Process Name'] == process_name].iloc[0]
        family = classify_ransomware_family(process_features)
        locker_text.insert(tk.END, f"{process_name} - {family}\n")

# Create the main window
root = tk.Tk()
root.title("Ransomware Detection")
root.geometry("800x600")  # Set the window size
root.configure(bg='#121212')  # Set background color to dark

# Create the main frame
main_frame = tk.Frame(root, bg='#121212', padx=10, pady=10)
main_frame.pack(fill=tk.BOTH, expand=True)

# Create the title label
title_label = tk.Label(main_frame, text="Ransomware Detection", font=("Helvetica", 24, "bold"), bg='#121212', fg='#FF5733')
title_label.pack(pady=10)

# Create the ransomware process list frame
process_frame = tk.Frame(main_frame, bg='#121212')
process_frame.pack(pady=10)

# Create the encrypter ransomware processes frame
encrypter_frame = tk.Frame(process_frame, bg='#121212')
encrypter_frame.pack(side=tk.LEFT, padx=10)

encrypter_label = tk.Label(encrypter_frame, text="Encrypter Ransomware Processes", font=("Helvetica", 16, "bold"), bg='#121212', fg='#FF5733')
encrypter_label.pack(pady=5)
encrypter_text = tk.Text(encrypter_frame, height=15, width=40, wrap=tk.WORD, bg='#1e1e1e', fg='white', insertbackground='white', bd=2, relief='solid')
encrypter_text.pack()

# Create the locker ransomware processes frame
locker_frame = tk.Frame(process_frame, bg='#121212')
locker_frame.pack(side=tk.LEFT, padx=10)

locker_label = tk.Label(locker_frame, text="Locker Ransomware Processes", font=("Helvetica", 16, "bold"), bg='#121212', fg='#FF5733')
locker_label.pack(pady=5)
locker_text = tk.Text(locker_frame, height=15, width=40, wrap=tk.WORD, bg='#1e1e1e', fg='white', insertbackground='white', bd=2, relief='solid')
locker_text.pack()

# Create the buttons frame
buttons_frame = tk.Frame(main_frame, bg='#121212')
buttons_frame.pack(pady=10)

# Create the "Monitor" button
monitor_button = tk.Button(buttons_frame, text="Monitor", command=monitor, width=15, bg='#282828', fg='white', bd=2, relief='solid')
monitor_button.pack(side=tk.LEFT, padx=5)

# Create the "Detect" button
detect_button = tk.Button(buttons_frame, text="Detect", command=detect, width=15, bg='#282828', fg='white', bd=2, relief='solid')
detect_button.pack(side=tk.LEFT, padx=5)

# Create the result label for displaying percentages
result_label = tk.Label(main_frame, text="", font=("Helvetica", 14), bg='#121212', fg='white')
result_label.pack(pady=10)

# Run the application
root.mainloop()
