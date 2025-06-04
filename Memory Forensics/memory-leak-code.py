import time

print("Starting aggressive memory leak demo...")

leak_list = []  # Store allocated memory chunks

try:
    while True:
        # Allocate 100MB of binary data per iteration
        chunk = b'A' * (100 * 1024 * 1024)  # 100 MB binary block
        leak_list.append(chunk)            # Intentional memory leak

        print(f"Leaked another 100MB... Total memory leaked: {len(leak_list) * 100} MB")
        time.sleep(1)  # Slight delay to make the spike noticeable but controlled

except KeyboardInterrupt:
    print("\nMemory leak demo interrupted by user.")