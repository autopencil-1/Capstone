import subprocess
import time
import statistics
import os
import concurrent.futures

def run_single_execution(binary, argument):
    """
    단일 실행에 대한 시간을 측정하여 반환하는 함수
    """
    start_time = time.perf_counter()
    try:
        subprocess.run([binary, argument], 
                       stdout=subprocess.DEVNULL, 
                       stderr=subprocess.DEVNULL, 
                       check=True)
    except subprocess.CalledProcessError:
        return None # 에러 발생 시 None 반환
    
    end_time = time.perf_counter()
    return end_time - start_time

def run_benchmark_multithread():
    # 1. 설정
    binaries = ["./plain_opt_hyperkenken", "./ollvm_bcf_hyperkenken", "./ollvm_fla_hyperkenken", "./ollvm_bcf_fla_hyperkenken", "./custom_hyperkenken"] 
    argument = "hyper_kenken_solution.txt"
    iterations = 100
    
    # 병렬 처리를 위한 워커 수 설정 (기본값: CPU 코어 수 + 4)
    # 너무 높으면 오버헤드가 커집니다.
    max_workers = os.cpu_count() or 4 

    benchmark_data = {}

    print(f"--- 벤치마크 시작 (반복: {iterations}회) ---")

    # 2. 실행 및 측정
    for binary in binaries:
        if not os.path.exists(binary):
            print(f"오류: '{binary}' 파일을 찾을 수 없습니다.")
            continue

        print(f"[{binary}] {iterations}회 병렬 실행 중...", end='', flush=True)
        
        durations = []
        
        # ThreadPoolExecutor를 사용하여 병렬 실행
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # iterations 횟수만큼 run_single_execution 함수를 예약
            futures = [executor.submit(run_single_execution, binary, argument) for _ in range(iterations)]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    durations.append(result)

        benchmark_data[binary] = durations
        print(" 완료.")

    # 3. 데이터 분석 및 출력
    if "./plain_opt_hyperkenken" not in benchmark_data or not benchmark_data["./plain_opt_hyperkenken"]:
        print("오류: 기준이 되는 './plain_opt_hyperkenken' 데이터가 충분하지 않습니다.")
        return

    plain_mean = statistics.mean(benchmark_data["./plain_opt_hyperkenken"])
    print("\n" + "="*75)
    print(f"{'Binary':<15} | {'Mean (sec)':<15} | {'Std Dev':<15} | {'Slowdown (x)':<15}")
    print("-" * 75)

    for binary in binaries:
        if binary in benchmark_data and benchmark_data[binary]:
            times = benchmark_data[binary]
            mean_time = statistics.mean(times)
            stdev_time = statistics.stdev(times) if len(times) > 1 else 0.0
            
            ratio = mean_time / plain_mean
            
            print(f"{binary:<15} | {mean_time:.3f} s      | {stdev_time:.3f}        | {ratio:.2f}x")
        else:
            print(f"{binary:<15} | {'실행 실패':<15} | {'-':<15} | {'-':<15}")
    
    print("="*75)

if __name__ == "__main__":
    if not os.path.exists("hyper_kenken_solution.txt"):
        print("경고: 'hyper_kenken_solution.txt' 파일이 현재 경로에 없습니다.")
        
    run_benchmark_multithread()