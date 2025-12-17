

import subprocess
import time
import statistics
import os
import sys

def run_benchmark():
    binaries = ["./plain_hyperkenken", "./ollvm_bcf_hyperkenken", "./ollvm_fla_hyperkenken", "./ollvm_bcf_fla_hyperkenken", "./chall"] 
    argument = "hyper_kenken_solution.txt"
    iterations = 20
    
    # 결과를 저장할 딕셔너리
    benchmark_data = {}

    print(f"--- 벤치마크 시작 (반복 횟수: {iterations}회) ---")

    # 2. 실행 및 시간 측정
    for binary in binaries:
        if not os.path.exists(binary):
            print(f"오류: '{binary}' 파일을 찾을 수 없습니다.")
            continue
            
        print(f"[{binary}] 실행 중...", end='', flush=True)
        durations = []
        
        try:
            for i in range(iterations):
                start_time = time.perf_counter()
                
                # 바이너리 실행 (stdout, stderr는 벤치마크 출력을 위해 숨김 처리)
                subprocess.run([binary, argument], 
                               stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL, 
                               check=True)
                
                end_time = time.perf_counter()
                duration=end_time - start_time
                print(binary, i+1, duration)
                durations.append(duration)
                
            benchmark_data[binary] = durations
            print(" 완료.")
            
        except subprocess.CalledProcessError:
            print(f"\n오류: {binary} 실행 중 에러가 발생했습니다.")
        except Exception as e:
            print(f"\n오류: {e}")

    # 3. 데이터 분석 및 출력
    if "./plain_hyperkenken" not in benchmark_data:
        print("오류: 기준이 되는 './plain_hyperkenken' 데이터가 없습니다.")
        return

    # plain의 평균 시간 계산 (기준점)
    plain_mean = statistics.mean(benchmark_data["./plain_hyperkenken"])
    
    print("\n" + "="*75)
    print(f"{'Binary':<15} | {'Mean (sec)':<15} | {'Std Dev':<15} | {'Slowdown (x)':<15}")
    print("-" * 75)

    for binary in binaries:
        if binary in benchmark_data:
            times = benchmark_data[binary]
            mean_time = statistics.mean(times)
            stdev_time = statistics.stdev(times)
            
            # 배속 계산 (plain 대비 얼마나 느린지)
            # 1.0x = plain과 같음, 2.0x = plain보다 2배 느림
            ratio = mean_time / plain_mean
            
            print(f"{binary:<15} | {mean_time:.6f} s      | {stdev_time:.6f}        | {ratio:.2f}x")
    
    print("="*75)

if __name__ == "__main__":
    # solution.txt 존재 여부 확인
    if not os.path.exists("hyper_kenken_solution.txt"):
        print("경고: 'solution.txt' 파일이 현재 경로에 없습니다.")
        # 파일이 없어도 실행하려면 아래 줄을 주석 처리하세요.
        # sys.exit(1)
        
    run_benchmark()