import pandas as pd
from sklearn.metrics import classification_report
import joblib

# Path to the preprocessed dataset
preprocessed_csv_path = r"C:\Users\monso\OneDrive\Desktop\Repos\Ransomware_detection\data_csv\preprocessed_procmon_log.csv"

# Load the preprocessed dataset
data = pd.read_csv(preprocessed_csv_path)

# Load the trained model
model_filename = r"C:\Users\monso\OneDrive\Desktop\Repos\Ransomware_detection\models\gradient_boosting_modelli.h5"
model_dict = joblib.load(model_filename)

# Extract the model and label encoder from the dictionary
model = model_dict["model"]
label_encoder = model_dict["label_encoder"]

# Make predictions
predictions = model.predict(data)

# Count the predictions for each class
prediction_counts = pd.Series(predictions).value_counts()
print("Prediction Counts:")
print(prediction_counts)

#  map the numerical predictions back to the original labels
label_mapping = {index: label for index, label in enumerate(label_encoder.classes_)}
prediction_labels = pd.Series(predictions).map(label_mapping)
prediction_counts_labels = prediction_labels.value_counts()
print("Prediction Counts with Labels:")
print(prediction_counts_labels)

# Print the classification report (if you have the true labels for comparison)
# true_labels_path = r"C:\Users\monso\OneDrive\Desktop\Repos\Ransomware_detection\data_csv\true_labels.csv"
# true_labels = pd.read_csv(true_labels_path)['family']  # Assuming the true labels are in a column named 'family'
# print("Classification Report:")
# print(classification_report(true_labels, predictions))
