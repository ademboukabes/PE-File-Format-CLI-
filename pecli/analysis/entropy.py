import math
from typing import List

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    occurences = [0] * 256
    for byte in data:
        occurences[byte] += 1

    entropy = 0
    for i in range(256):
        p_x = occurences[i] / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)

    return entropy
