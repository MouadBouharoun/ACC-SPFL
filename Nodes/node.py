import pickle
import socket
import msgpack
import numpy as np
import msgpack_numpy as m
import time
import tensorflow as tf
import pandas as pd
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM
from tensorflow.keras.utils import to_categorical
from tensorflow.keras import metrics
from tensorflow.keras import backend as K
from tensorflow.keras.losses import categorical_crossentropy
import matplotlib.pyplot as plt
# Create a UDP socket and bind it to a specific IP address and port
node_address = ('IP', Port)  # Example IP address and port
node_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
node_socket.bind(peer2_address)

# Loading nginx dataset
df=pd.read_csv("/home/application/temporary/datasets/NF-BoT-IoT.csv")
src_ipv4_idx = {name: idx for idx, name in enumerate(sorted(df["IPV4_SRC_ADDR"].unique()))}
dst_ipv4_idx = {name: idx for idx, name in enumerate(sorted(df["IPV4_DST_ADDR"].unique()))}
attack_idx = {name: idx for idx, name in enumerate(sorted(df["Attack"].unique()))}
# data preparation
df["IPV4_SRC_ADDR"] = df["IPV4_SRC_ADDR"].apply(lambda name: src_ipv4_idx[name])
df["IPV4_DST_ADDR"] = df["IPV4_DST_ADDR"].apply(lambda name: dst_ipv4_idx[name])
df["Attack"] = df["Attack"].apply(lambda name: attack_idx[name])
######################################
X=df.iloc[:, :-1].values
y=df.iloc[:, -1].values
y=to_categorical(y,num_classes=7)

X=np.reshape(X, (X.shape[0], X.shape[1], 1))
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
# Creating the model
model = Sequential()
model.add(LSTM(units=64, activation='relu', input_shape=(X.shape[1], 1)))
model.add(Dense(units=7, activation='softmax'))
model.compile(loss="categorical_crossentropy", optimizer="adam", metrics=["accuracy", metrics.Precision(), metrics.Recall()])
# Start federated learning process
rounds=1
while rounds<50:
    print('FL round', rounds)
    model.fit(X_train, y_train, epochs=1, batch_size=32)
    loss, accuracy, precision, recall = model.evaluate(X_test, y_test)
    array_list=model.get_weights()
    print('Test accuracy ', accuracy)
    print('Loss', loss)
    print("sending gradients")
    with tf.GradientTape() as tape:
        predictions = model(X_train, training=True)
        loss = tf.keras.losses.categorical_crossentropy(y_train, predictions)
    gradients = tape.gradient(loss, model.trainable_variables)
    for gradient in gradients:
        MAX_MESSAGE_SIZE = 65507
        data = pickle.dumps(gradient)
        chunks = [data[i:i+MAX_MESSAGE_SIZE] for i in range(0, len(data), MAX_MESSAGE_SIZE)]
        for chunk in chunks:
            peer2_socket.sendto(chunk, ('IP2', Port2))
    print("receiving gradients")
    MAX_PACKET_SIZE = 65535
    received_data = b''
    expected_data = pickle.dumps(gradients)
    total_expected_data_length = len(expected_data)
    while True:
       data , address = peer2_socket.recvfrom(MAX_PACKET_SIZE)
       received_data += data
       if len(received_data) >= total_expected_data_length:
          break
    gradients = pickle.loads(received_data)
    optimizer = tf.keras.optimizers.Adam(learning_rate=0.01)
    optimizer.apply_gradients(zip(gradients, model.trainable_variables))
    rounds +=1
#save model
model.save('Global_model_nginx')
# end of federated learning process
#close socket
peer2_socket.close()


