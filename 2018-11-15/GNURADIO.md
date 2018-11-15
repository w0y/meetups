# gnuradio Hints

## AVR

## Analyzing the Signal without gnuradio

```python
# Imports for loading and plotting the data
%matplotlib qt5
import numpy as np
import matplotlib.pyplot as plt

# Read the signal from the file. The data is stored in complex64
# format, meaning real + imaginary part as float32 consecutively
s = np.fromfile('./signal.dump', dtype=np.float32)
r = s[::2]
i = s[1::2]

# Initialize plotting
fig = plt.figure()
ax = plt.axes()

# Plot real/imaginary parts of the signal
ax.plot(np.linspace(0, 1, len(i)), i)
ax.plot(np.linspace(0, 1, len(r)), r)

# Set signal high/low to 1/0
r[r < 0.5] = 0
r[r > 0.5] = 1

# Find start/end of the signal
start = np.where(r==1)[0]
end = np.where(r==1)[-1]
length = int(np.ceil((end - start) / 100))

# Plot signal from start to end
ax.clear()
ax.plot(np.linspace(0, 1, end - start), r[start:end])

# Group ones and zeroes
s = [r[i * 100 + start] for i in range(length)]

# Plot signal once more
ax.clear()
ax.plot(np.linspace(0, 1, length), np.array(s))
```