guii.py is the main file. Run it to see the results

Read(Compulsory):

Data_flow_of_guii_py.docs
Risks_taken.txt
Limitations.txt

Change all the paths in guii.py in accordance to your paths. 

# Data Flow of `guii.py`

The script `guii.py` provides a graphical user interface (GUI) for monitoring system calls and detecting ransomware types. The workflow involves two main operations: monitoring system calls and detecting ransomware. Below is a detailed explanation of the data flow and operations in the script.

---

## **1. Start the GUI**

### Initialization
- When `guii.py` is executed, it initializes the main window using **tkinter**.
- Two primary buttons are created:
  - **"Monitor"**: Triggers the monitoring process.
  - **"Detect"**: Initiates ransomware detection.

---

## **2. Monitoring System Calls**

### **Monitor Button Clicked**
- When the **"Monitor"** button is clicked, the `monitor()` function is triggered.

### **Workflow Steps**

#### **Start Procmon**
1. The `start_procmon()` function starts `Procmon64.exe` with specific arguments:
   - Runs quietly and minimized.
   - Captures system calls.
   - Saves the log file as `procmon_log.pml`.
   - Monitors for a specified duration (e.g., 10 seconds).

#### **Stop Procmon**
2. After the monitoring duration, the `stop_procmon()` function terminates `Procmon64.exe`.

#### **Convert Log to CSV**
3. The `convert_pml_to_csv()` function converts `procmon_log.pml` into a CSV file named `procmon_log.csv`.

#### **Load and Rename Data**
4. The CSV file is loaded into a **pandas DataFrame**.
   - The columns are renamed to:
     ```
     ["log", "tree_process_name", "proc_pid", "api", "process_path", "description", "info"]
     ```

#### **Preprocess and Normalize Data**
5. The `makerr()` function is called to:
   - Preprocess and normalize the features.
   - Encode categorical features.
   - Normalize numerical features to a range of 0 to 1.
   - Save the preprocessed data to `preprocessed_procmon_log.csv`.

#### **Completion Message**
6. A message box displays:
   - Indicates that monitoring is complete.
   - Informs the user to proceed to the detection phase.

---

## **3. Detecting Ransomware**

### **Detect Button Clicked**
- Clicking the **"Detect"** button triggers the `detect()` function.

### **Workflow Steps**

#### **Load Preprocessed Data**
1. Loads the preprocessed data from `preprocessed_procmon_log.csv`.

#### **Load Trained Model**
2. Loads the pre-trained model (`gradient_boosted_trees_model.h5`).

#### **Make Predictions**
3. The model predicts ransomware types using the preprocessed data.
   - Predictions are mapped to descriptive labels using a dictionary:
     ```
     {"G": "Goodware", "L": "Locker Ransomware", "E": "Encrypter Ransomware"}
     ```
   - Calculates the percentage of each type.

#### **Display Results**
4. Displays a message box showing the detection results:
   - Percentages of:
     - Goodware
     - Locker Ransomware
     - Encrypter Ransomware

---

## **Summary of Script Functions and Workflow**

### **1. GUI Initialization**
- **tkinter** initializes the main window with two buttons:
  - **"Monitor"**
  - **"Detect"**

### **2. Monitoring System Calls (`monitor()` Function)**
- **Starts Procmon64.exe** to capture system calls.
- **Stops Procmon64.exe** after a specified duration.
- **Converts log file** to CSV format.
- **Loads and renames data** for standardization.
- **Calls `makerr()`** to preprocess and normalize data.
- **Saves preprocessed data** to a CSV file.
- **Displays completion message.**

### **3. Preprocessing Data (`makerr()` Function)**
- Encodes categorical features.
- Normalizes numerical features.
- Saves preprocessed data to a CSV file.
- Displays debug information.

### **4. Detecting Ransomware (`detect()` Function)**
- Loads preprocessed data.
- Loads the trained model.
- Makes predictions on the data.
- Maps predictions to descriptive labels.
- Counts and calculates percentages of each type.
- Displays detection results.

---

## **Filename**: `guii.py`

This script provides an intuitive GUI for users to:
- Monitor system calls.
- Detect ransomware using a pre-trained machine learning model.

The process is automated from data capture to prediction, offering a user-friendly interface and clear detection results.
