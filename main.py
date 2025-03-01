import os
import math
import pywt
import winreg
import struct

def calculate_entropy(data):
    if not data:
        return 0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    entropy = -sum((count / len(data)) * math.log2(count / len(data)) for count in byte_counts if count)
    return entropy

def wavelet_analysis(data):
    if len(data) < 8:
        return 0  
    try:
        coeffs = pywt.wavedec(data, 'haar', level=min(3, pywt.dwt_max_level(len(data), 'haar')))
        max_coeff = max(abs(c) for coeff in coeffs for c in coeff)
        return max_coeff
    except ValueError:
        return 0

def pearson_criterion(data):
    expected = len(data) / 256
    chi_square = sum(((data.count(i) - expected) ** 2) / expected for i in range(256))
    return chi_square

def monte_carlo_test(data):
    if len(data) < 2:
        return 0
    inside_circle = 0
    total_points = len(data) // 2
    for i in range(0, total_points * 2, 2):
        x, y = data[i] / 255.0, data[i+1] / 255.0
        if x**2 + y**2 <= 1:
            inside_circle += 1
    return (inside_circle / total_points) * 4

def scan_registry_for_sksi():
    sksi_signatures = ["CryptoPro", "TrueCrypt", "BitLocker"]
    results = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE") as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                subkey = winreg.EnumKey(key, i)
                for sig in sksi_signatures:
                    if sig.lower() in subkey.lower():
                        results[subkey] = True
    except Exception:
        pass
    return results

def analyze_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        print(f"Запуск анализа файла: {filepath}, размер данных: {len(data)} байт")
        entropy = calculate_entropy(data)
        wavelet_coeff = wavelet_analysis(data)
        pearson_val = pearson_criterion(data)
        monte_carlo = monte_carlo_test(data)
        print(f"Имя файла: {os.path.basename(filepath)}")
        print(f"Размер файла: {len(data)} байт")
        print(f"Энтропия: {entropy}")
        print(f"Критерий Пирсона: {pearson_val}")
        print(f"Max Вейвлет-коэффициент: {wavelet_coeff}")
        print(f"Монте-Карло значение: {monte_carlo}")
    except Exception as e:
        print(f"Ошибка анализа {filepath}: {e}")

def scan_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            analyze_file(os.path.join(root, file))

if __name__ == "__main__":
    scan_path = input("Введите путь к файлу или папке для анализа (по умолчанию ./test_files): ").strip() or "./test_files"
    if os.path.isfile(scan_path):
        analyze_file(scan_path)
    elif os.path.isdir(scan_path):
        scan_directory(scan_path)
    else:
        print("Ошибка: Указанный путь не является файлом или папкой.")
    
    sksi_results = scan_registry_for_sksi()
    print("Обнаруженные следы СКЗИ:", sksi_results)
