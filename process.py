"""
This is used to process data and not explicitly necessary to run the application.
"""

import numpy as np
import matplotlib.pyplot as plt
import sys
import matplotlib as mpl

from os import listdir
from os.path import isfile, join
from scipy.optimize import curve_fit


def fill_array(xs, ys):
    lowest_index = xs[0]
    filled_xs = np.concatenate((np.arange(lowest_index),  xs), axis=None)
    filled_ys = np.concatenate((np.zeros(lowest_index), ys), axis=None)
    indices = []

    for i in range(lowest_index, len(filled_xs) - 1):
        if filled_xs[i] < filled_xs[i+1] - 1:
            indices.append((i, (filled_ys[i+1] + filled_ys[i]) // 2))

    ys = list(filled_ys)
    for i, val in reversed(indices):
        ys.insert(i, val)
    filled_xs = np.arange(len(ys))
    return filled_xs, ys


def calc_connection_idx(data_arrays):
    running_idx = []
    indices = []
    for idx in range(800):
        for data_idx, data in enumerate(data_arrays):
            if data[1][idx] != 0 and data_idx not in running_idx:
                indices.append(idx + 10)
                running_idx.append(data_idx)
    indices.append(indices[-1] + 50)
    return indices


def calc_total_data(lowest_length, data_arrays):
    temp_arr = []
    for idx in range(lowest_length):
        temp_arr.append(0)
        for data in data_arrays:
            temp_arr[idx] += data[1][idx]

    return temp_arr


def calc_usage(total_data, indices, heartbeat_on):
    usage_list = []
    previous = 0
    for idx in range(len(indices) - 1):
        if heartbeat_on:
            ts = indices[idx + 1] - indices[idx] - 20
            data = total_data[indices[idx + 1] - 20] - total_data[indices[idx]]
        else:
            ts = 20
            data = total_data[indices[idx]]
        if heartbeat_on:
            usage_list.append(data / ts / 0.15)
        else:
            usage_list.append(data - previous)
        previous = data

    return usage_list


def exponenial_func(x, a, b, c):
    return a*np.exp(-b*x)+c


def show_result(directory, heartbeat_on):
    files = [f for f in listdir(directory) if isfile(join(directory, f)) and "data_" in f if f != "data_94B86DF994AC.txt"]

    alldata = {file:np.genfromtxt(directory + file, delimiter=' ', dtype=int) for file in files}
    lowest_key, lowest_index = next(iter(alldata.items()))
    lowest_index = lowest_index[0, 0]
    cmap = mpl.cm.rainbow
    lowest_length = sys.maxsize
    data_arrays = []

    if heartbeat_on:
        len_plot = 800
    else:
        len_plot = 1000

    for file, data in alldata.items():
        if data[0, 0] < lowest_index:
            lowest_index = data[0, 0]

    for idx, (file, data) in enumerate(alldata.items()):
        data[:, 0] -= lowest_index
        plt.plot(data[:len_plot, 0], data[:len_plot, 1], c=cmap(idx / float(len(files))), label=file)
        xs, ys = fill_array(data[:, 0], data[:, 1])
        if len(xs) < lowest_length:
            lowest_length = len(xs)

        data_arrays.append((xs, ys))

    indices = calc_connection_idx(data_arrays)[1:]
    total_data = calc_total_data(lowest_length, data_arrays)
    usage = calc_usage(total_data, indices, heartbeat_on)


    plt.plot(np.arange(len(total_data))[:len_plot], total_data[:len_plot], label='Total bytes send')
    plt.xlabel('Timestamp')
    plt.ylabel('Total bytes sent')
    plt.title('Total bytes usage per node over time.')
    plt.legend()
    if heartbeat_on:
        plt.savefig('documents/figures/heartbeat_total', bbox_inches = "tight")
    else:
        plt.savefig('documents/figures/onchange_total', bbox_inches = "tight")
    plt.show()

    # Fit exponential function
    xs = np.arange(len(usage)) + 2
    popt, pcov = curve_fit(exponenial_func, xs, usage, p0=(1, 1e-6, 1))
    xx = np.arange(2, 32)
    yy = exponenial_func(xx, *popt)
    plt.plot(xs, usage,'o', label='actual data')
    plt.plot(xx, yy, label='fit')
    plt.legend()
    if heartbeat_on:
        plt.title('Exponent fit on byte/s usage per connected node for heartbeat')
        plt.xlabel('Total connected nodes')
        plt.ylabel('Bytes per second')
        plt.savefig('documents/figures/heartbeat_fit', bbox_inches = "tight")
    else:
        plt.title('Exponent fit on bytes usage per node connection for on change')
        plt.xlabel('Total connected nodes')
        plt.ylabel('Bytes sent')
        plt.savefig('documents/figures/onchange_fit_2', bbox_inches = "tight")
    plt.show()

def compare_alg():
    on_change_path =  "logs/MON1_ARG1/"
    heartbeat_path = "logs/data_1/"
    directories = [on_change_path, heartbeat_path]
    usages = []

    for i, directory in enumerate(directories):
        files = [f for f in listdir(directory) if isfile(join(directory, f)) and "data_" in f if f != "data_94B86DF994AC.txt"]

        alldata = {file:np.genfromtxt(directory + file, delimiter=' ', dtype=int) for file in files}
        lowest_key, lowest_index = next(iter(alldata.items()))
        lowest_index = lowest_index[0, 0]
        cmap = mpl.cm.rainbow
        lowest_length = sys.maxsize
        data_arrays = []

        for file, data in alldata.items():
            if data[0, 0] < lowest_index:
                lowest_index = data[0, 0]

        for idx, (file, data) in enumerate(alldata.items()):
            data[:, 0] -= lowest_index
            xs, ys = fill_array(data[:, 0], data[:, 1])
            if len(xs) < lowest_length:
                lowest_length = len(xs)
            data_arrays.append((xs, ys))

        if i == 0:
            heartbeat_on = 0
        else:
            heartbeat_on = 1
        indices = calc_connection_idx(data_arrays)[1:]

        total_data = calc_total_data(lowest_length, data_arrays)
        usage = calc_usage(total_data, indices, heartbeat_on)

        # Fit exponential function
        xs = np.arange(len(usage)) + 2
        popt, pcov = curve_fit(exponenial_func, xs, usage, p0=(1, 1e-6, 1))
        xx = np.arange(2, 32)
        yy = exponenial_func(xx, *popt)
        usages.append(yy)

        if heartbeat_on:
            startup_heartbeat = calc_usage(total_data, indices, 0)
            # Fit exponential function
            xs = np.arange(len(startup_heartbeat)) + 2
            xx = np.arange(2, 32)
            popt, pcov = curve_fit(exponenial_func, xs, startup_heartbeat, p0=(1, 1e-6, 1), maxfev=2000)
            yy = exponenial_func(xx, *popt)
            print(usages[0])
            print(yy)
            usages[0] = usages[0] - yy

    plt.figure(figsize=(10, 6))
    plt.plot( np.arange(len(usages[0])) + 2, usages[0] / usages[1])
    plt.xlabel('Total connected nodes')
    plt.ylabel('Seconds needed for heartbeat traffic to surpass total bytes of on change')
    plt.title('Time needed for on change to surpass heartbeat performance per node')
    plt.tight_layout()
    plt.savefig('documents/figures/compared', bbox_inches = "tight")
    plt.show()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        heartbeat_on = int(sys.argv[1])
    else:
        heartbeat_on = 0

    if heartbeat_on == 0:
        directory =  "logs/MON1_ARG1/"
    else:
        directory = "logs/data_1/"

    if False:
        show_result(directory, heartbeat_on)
    else:
        compare_alg()
