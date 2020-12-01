"""
Create plots from the processed data and not explicitly necessary to run the application.
"""

import numpy as np
import matplotlib.pyplot as plt
from scipy.optimize import curve_fit

def lin_func(x, a, b):
    return x*a + b


data = [np.genfromtxt("logs/ping_rtt.txt"),
        np.genfromtxt("logs/ping_rtt_2hop.txt"),
        np.genfromtxt("logs/ping_rtt_3hop.txt")]

stats = []
for d in data:
    stats.append([sum(d) / len(d), np.std(d)])
stats = np.array(stats)

plt.errorbar([1, 2, 3], stats[:, 0], stats[:, 1], linestyle="None", marker="o", ecolor='r')
plt.title('Round trip time versus amount of hops')
plt.xlabel("Amount of hops")
plt.ylabel("RTT (ms)")
plt.xticks([1,2,3])
plt.savefig('documents/figures/latency', bbox_inches = "tight")
plt.show()

popt, pcov = curve_fit(lin_func, [1, 2, 3], stats[:, 0])
xx = np.arange(1, 10)
yy = lin_func(xx, *popt)

popt, pcov = curve_fit(lin_func, [1, 2, 3], stats[:, 1])
ee = lin_func(xx, *popt)

plt.errorbar(xx, yy, ee, linestyle="None", marker="o", ecolor='r')
plt.title('Fit on round trip time versus amount of hops')
plt.xlabel("Amount of hops")
plt.ylabel("RTT (ms)")
plt.savefig('documents/figures/latency_fit', bbox_inches = "tight")
plt.show()
