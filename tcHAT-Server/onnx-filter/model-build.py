from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score
from skl2onnx.common.data_types import StringTensorType
from skl2onnx import convert_sklearn
from pandas import read_csv

data = read_csv('_data.csv')

X = data['text']
Y = data['label']

vectoriser = TfidfVectorizer(stop_words='english')
model = MultinomialNB()
pipeline = make_pipeline(vectoriser, model)
pipeline.fit(X, Y)

y_pred = pipeline.predict(X)
accuracy = accuracy_score(Y, y_pred)

print(f"Accuracy score {accuracy * 100:.2f}%")


onnx_init = [('input', StringTensorType([None]))]
onnx_model = convert_sklearn(pipeline, initial_types=onnx_init)

with open('filter.onnx', 'wb') as file:
    file.write(onnx_model.SerializeToString())

print('Built the model')