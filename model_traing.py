import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import pickle

# Load the dataset
annex_a_file_path = 'Dataset with 50 chosen features.csv'  # Update the path if necessary
annex_a_df = pd.read_csv(annex_a_file_path)

# Define the important features and target variable
important_features = [
     'file_created', 'file_read', 'urls', 'apistats', 
     'dll_loaded', 'directory_enumerated', 'action', 
     'proc_pid','tcp','udp','regkey_read','wmi_query','regkey_written',
]
target_variable = 'family'

# Encode the target variable
label_encoder = LabelEncoder()
annex_a_df[target_variable] = label_encoder.fit_transform(annex_a_df[target_variable])

# Split the data into training and testing sets
X = annex_a_df[important_features]
y = annex_a_df[target_variable]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train a Gradient Boosting Classifier
model = GradientBoostingClassifier(random_state=42)
model.fit(X_train, y_train)

# Make predictions
y_pred = model.predict(X_test)

# Evaluate the model
classification_rep = classification_report(y_test, y_pred, target_names=label_encoder.classes_)
conf_matrix = confusion_matrix(y_test, y_pred)

# Print the classification report
print("Classification Report:\n", classification_rep)

# Visualize the confusion matrix
plt.figure(figsize=(10, 7))
sns.heatmap(conf_matrix, annot=True, fmt="d", cmap="Blues", xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.savefig('Figures/confusion_matrix.png')  # Save the plot
plt.show()

# Plot feature importance
feature_importance = model.feature_importances_
sorted_idx = feature_importance.argsort()

plt.figure(figsize=(10, 7))
plt.barh(range(len(sorted_idx)), feature_importance[sorted_idx], align='center')
plt.yticks(range(len(sorted_idx)), [important_features[i] for i in sorted_idx])
plt.xlabel('Feature Importance')
plt.title('Gradient Boosting Feature Importance')
plt.savefig('/Figures/feature_importance.png')  # Save the plot
plt.show()

# Save the results and model
annex_a_df.to_csv('annex_a_with_predictions.csv', index=False)
pd.DataFrame(conf_matrix, index=label_encoder.classes_, columns=label_encoder.classes_).to_csv('C:/Users/monso/OneDrive/Desktop/Repos/Ransomware_detection/Figures/confusion_matrix.csv')
model_output = {
    "model": model,
    "label_encoder": label_encoder
}

with open('models/gradient_boosting_modelli.h5', 'wb') as f:
    pickle.dump(model_output, f)
