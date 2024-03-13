import matplotlib.pyplot as plt
import numpy as np
import os

func = lambda x: '_stats' in x


def vizualize_hist(data):
    global missed_keys, all_keys, dir_path, file_name
    plt.hist(data, bins=30)
    plt.xlabel('Amount of keys in chunk')
    plt.ylabel('Frequency')
    frequency, bins = np.histogram(numbers, bins=30)
    plt.text(53, (max(frequency) * 6) // 7, f'Percantage of keys missed in HT: {round(100 * (missed_keys / all_keys), 2)}%', fontsize = 10)
    plt.title(file_name)
    plt.grid(True)
    plt.savefig(f'{dir_path}histograms/{file_name}.png')
    plt.show()
    plt.clf()

def vizualize_plot(data):
    global dir_path, file_name
    enum_data = enumerate(data)
    enum_data = list(filter(lambda x: x[1] == 0, enum_data))
    group_size = 2185 * 16 * 64
    grouped_data = dict()
    for val in enum_data:
        gid = val[0] // group_size
        if gid not in grouped_data:
            grouped_data[gid] = 0
        grouped_data[gid] += val[1]

    print('Data grouped for scatter')
    plt.scatter(grouped_data.keys(), grouped_data.values())
    plt.xlabel('Chunk_id')
    plt.ylabel('Chunk_size')
    plt.grid(True)
    plt.savefig(f'{dir_path}plots/{file_name}.png')
    plt.show()
    plt.clf()


for dir_path in os.getenv("SESSION_NAMES").replace('\"', '').split():
    if dir_path.strip() == '':
        continue
    dir_path += '_dir/'
    files = sorted(list(filter(func, os.listdir(dir_path))))
    print("Files for dir:", files)

    for file_name in files:
        file_path = dir_path + file_name
        with open(file_path, 'r') as file:
            data = file.read().strip().split(' ')
        
        print('\nDraw histograms for file:', file_name)

        numbers = [int(num) for num in data]
        initial_size = len(numbers)
        # vizualize_plot(numbers)

        numbers = list(filter(lambda x: x > 0, numbers))
        all_keys = sum(numbers)
        print('Length:', len(numbers))
        print('Sum:', all_keys)
        print('Percent of empty chunks:', 100 * (len(numbers) / initial_size))
    
        chunk_size = int(file_name.split('_')[0])
        numbers = list(filter(lambda x: x > chunk_size, numbers))
        missed_keys = sum(numbers) - chunk_size * len(numbers)
        
        print('Amount of keys with ex collison:', missed_keys)
        print('Amount of chunks with size > chunk_size:', len(numbers))
        print('Percent of missed keys:', 100 * (missed_keys / all_keys))
        print(numbers[:16])

        vizualize_hist(numbers)

        print('=================================================================================')