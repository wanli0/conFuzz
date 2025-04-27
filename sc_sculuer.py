#!/usr/bin/env python3
import os
import sys
import mmap
import time
import math
import random
import argparse
import subprocess
import concurrent.futures
import threading
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ====================== 命令行参数配置 ======================
def parse_args():
    parser = argparse.ArgumentParser(
        description="SA-Driven Fuzzer Resource Scheduler",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("-n", "--num-instances", type=int, required=True,
                        help="并行实例数量")
    parser.add_argument("-f", "--fuzzer", type=str, required=True,
                        help="模糊测试工具名称 (e.g. pfuzz)")
    parser.add_argument("-p", "--project", type=str, required=True,
                        help="测试目标项目 (e.g. openssl)")
    parser.add_argument("-t", "--test-scenario", type=str, required=True,
                        help="测试场景名称 (e.g. handshake_test)")
    parser.add_argument("-c", "--config-pool", nargs='+', required=True,
                        help="可用测试模板列表")
    parser.add_argument("-s", "--start-idx", type=int, default=1,
                        help="实例起始编号")
    parser.add_argument("-i", "--interval", type=int, default=60,
                        help="调度决策间隔（秒）")
    parser.add_argument("--init-temp", type=float, default=1000.0,
                        help="初始温度")
    parser.add_argument("--cool-rate", type=float, default=0.95,
                        help="降温速率")
    parser.add_argument("--min-temp", type=float, default=1.0,
                        help="最低温度")
    parser.add_argument("--max-stagnant", type=int, default=20,
                        help="最大停滞迭代次数")
    
    return parser.parse_args()

# ====================== 增强型覆盖率监控 ======================
class AsyncCoverageMonitor(CoverageMonitor):
    def __init__(self, instance_manager):
        super().__init__(instance_manager)
        self.refresh_lock = threading.Lock()
        self.worker = threading.Thread(target=self._async_refresh, daemon=True)
        self.worker.start()

    def _async_refresh(self):
        """异步刷新线程"""
        while True:
            with self.refresh_lock:
                active_instances = [
                    i for i, inst in self.instance_manager.instances.items()
                    if inst['active']
                ]
                
                # 分批次处理避免同时打开过多文件
                batch_size = 16
                for i in range(0, len(active_instances), batch_size):
                    batch = active_instances[i:i+batch_size]
                    self._process_batch(batch)
            
            time.sleep(5)  # 降低刷新频率

    def _process_batch(self, inst_ids):
        """批量处理实例刷新"""
        for inst_id in inst_ids:
            inst = self.instance_manager.instances[inst_id]
            edge_path = inst['shm_paths']['cov_edge']
            
            try:
                mtime = os.path.getmtime(edge_path)
                if mtime > self.last_update.get(inst_id, 0):
                    with open(edge_path, "r+b") as f:
                        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                            data = bytes(mm)
                            if data:
                                self.edge_coverage[inst_id] = data
                                self.last_update[inst_id] = mtime
            except Exception as e:
                print(f"[WARN] 实例 {inst_id} 数据刷新失败: {str(e)}")

    def get_merged_coverage(self, active_instances):
        """优化后的位运算合并"""
        if not active_instances:
            return 0

        # 使用numpy加速运算（需安装numpy）
        try:
            import numpy as np
            max_len = max(len(self.edge_coverage[i]) for i in active_instances)
            merged = np.zeros(max_len, dtype=np.uint8)
            
            for inst_id in active_instances:
                data = self.edge_coverage.get(inst_id, b'')
                np_data = np.frombuffer(data, dtype=np.uint8, count=min(len(data), max_len))
                merged[:len(np_data)] |= np_data
            
            return np.unpackbits(merged).sum()
        except ImportError:
            # 回退到原生Python实现
            return super().get_merged_coverage(active_instances)

class CoverageMonitor:
    def __init__(self, instance_manager):
        self.instance_manager = instance_manager
        self.edge_coverage = defaultdict(bytes)
        self.last_update = defaultdict(float)

    def _safe_read_shm(self, path):
        try:
            with open(path, "r+b") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    return bytes(mm)
        except Exception as e:
            print(f"[WARN] 无法读取 {path}: {str(e)}")
            return b''

    def refresh(self):
        for inst_id, inst in self.instance_manager.instances.items():
            if not inst['active']:
                continue
            
            edge_path = inst['shm_paths']['cov_edge']
            try:
                mtime = os.path.getmtime(edge_path)
                if mtime > self.last_update.get(inst_id, 0):
                    data = self._safe_read_shm(edge_path)
                    if data:
                        self.edge_coverage[inst_id] = data
                        self.last_update[inst_id] = mtime
            except Exception as e:
                print(f"[ERROR] 刷新实例 {inst_id} 数据失败: {str(e)}")

    @staticmethod
    def count_branches(data):
        return sum(bin(byte).count('1') for byte in data)

    def get_instance_coverage(self, inst_id):
        return self.count_branches(self.edge_coverage.get(inst_id, b''))

    def get_merged_coverage(self, active_instances):
        active_data = [self.edge_coverage[i] for i in active_instances]
        if not active_data:
            return 0

        merged = bytearray(active_data[0])
        for data in active_data[1:]:
            if len(data) > len(merged):
                merged.extend(b'\x00' * (len(data) - len(merged)))
            for i in range(len(data)):
                merged[i] |= data[i]
        return self.count_branches(merged)

# ====================== 资源池管理器 ======================

class OptimizedResourcePool(ResourcePool):
    def _init_pool(self):
        """并行初始化共享内存"""
        self.instances = {}
        self.shm_paths = {}

        # 生成所有实例配置
        instance_configs = [
            (i, {
                'cov_edge': f"/dev/shm/{self.args.project}_edge_{i}",
                'cov_bitmap': f"/dev/shm/{self.args.project}_bitmap_{i}"
            })
            for i in range(self.args.start_idx, 
                          self.args.start_idx + self.args.num_instances)
        ]

        # 使用线程池并行创建共享内存
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(self._create_shm_parallel, paths) 
                for _, paths in instance_configs
            ]
            concurrent.futures.wait(futures)

        # 初始化实例
        for inst_id, paths in instance_configs:
            self.instances[inst_id] = {
                'id': inst_id,
                'active': False,
                'process': None,
                'current_config': None,
                'shm_paths': paths,
                'weight': 1.0
            }
            self.shm_paths[inst_id] = paths

    def _create_shm_parallel(self, paths):
        """并行创建共享内存的辅助方法"""
        for path in paths.values():
            if not Path(path).exists():
                try:
                    subprocess.run(
                        f"dd if=/dev/zero of={path} bs=10M count=1 status=none",
                        shell=True, check=True
                    )
                    os.chmod(path, 0o666)
                except subprocess.CalledProcessError as e:
                    print(f"[ERROR] 创建 {path} 失败: {str(e)}")

class ResourcePool:
    def __init__(self, args):
        self.args = args
        self.instances = {}
        self.shm_paths = {}
        self._init_pool()

    def _init_pool(self):
        """初始化资源池，每个实例分配固定共享内存"""
        for i in range(self.args.start_idx, 
                      self.args.start_idx + self.args.num_instances):
            shm_paths = {
                'cov_edge': f"/dev/shm/{self.args.project}_edge_{i}",
                'cov_bitmap': f"/dev/shm/{self.args.project}_bitmap_{i}"
            }
            
            # 创建共享内存文件（整个生命周期只创建一次）
            self._create_shm(shm_paths)
            
            self.instances[i] = {
                'id': i,
                'active': False,
                'process': None,
                'current_config': None,
                'shm_paths': shm_paths,
                'weight': 1.0
            }
            self.shm_paths[i] = shm_paths

    def _create_shm(self, paths):
        """创建共享内存文件（仅在初始化时执行）"""
        for path in paths.values():
            if not Path(path).exists():
                subprocess.run(
                    f"dd if=/dev/zero of={path} bs=10M count=1 status=none",
                    shell=True, check=True
                )
                os.chmod(path, 0o666)

    def switch_config(self, inst_id, new_config):
        """切换实例配置"""
        inst = self.instances[inst_id]
        
        # 停止当前测试
        if inst['process']:
            inst['process'].terminate()
            try:
                inst['process'].wait(timeout=5)
            except:
                pass
        
        # 启动新配置
        env = os.environ.copy()
        env.update({
            "LUCKY_GLOBAL_MMAP_FILE": inst['shm_paths']['cov_edge'],
            "SHM_ENV_VAR": inst['shm_paths']['cov_bitmap'],
            "FUZZER_INSTANCE_ID": str(inst_id)
        })
        
        try:
            proc = subprocess.Popen(
                ["timeout", "86400", "mono",
                 "/root/PFuzz/output/linux_x86_64_release/bin/peach.exe",
                 new_config],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT
            )
            inst.update({
                'process': proc,
                'active': True,
                'current_config': new_config,
                'weight': self._calc_weight(new_config)
            })
            print(f"[+] 实例 {inst_id} 切换至配置: {Path(new_config).name}")
        except Exception as e:
            print(f"[ERROR] 实例 {inst_id} 配置切换失败: {str(e)}")
            inst['active'] = False

    def _calc_weight(self, config_path):
        """动态计算配置权重"""
        name = Path(config_path).stem.lower()
        if 'heavy' in name: return 2.0
        if 'medium' in name: return 1.5
        return 1.0

    def activate(self, inst_id, config):
        """激活实例"""
        if not self.instances[inst_id]['active']:
            self.switch_config(inst_id, config)

    def deactivate(self, inst_id):
        """暂停实例（保留共享内存）"""
        inst = self.instances[inst_id]
        if inst['process']:
            inst['process'].terminate()
            try:
                inst['process'].wait(timeout=5)
            except:
                pass
        inst.update({'active': False, 'process': None})
        print(f"[.] 实例 {inst_id} 已暂停")

    def cleanup(self):
        """最终清理所有共享内存"""
        for paths in self.shm_paths.values():
            for path in paths.values():
                try:
                    os.remove(path)
                    print(f"清理共享内存: {path}")
                except:
                    pass

# ====================== 强化模拟退火核心 ======================
class HighPerformanceSAScheduler(EnhancedSAScheduler):
    def _generate_candidate(self, current_set):
        """针对大规模实例优化的候选解生成"""
        # 批量操作：每次调整5%的实例（至少1个）
        num_changes = max(1, int(len(current_set)*0.05))
        
        # 选择策略
        if random.random() < 0.8:  # 80%概率基于效率
            return self._batch_optimize(current_set, num_changes)
        else:  # 20%概率随机探索
            return self._batch_random(current_set, num_changes)

    def _batch_optimize(self, current_set, num_changes):
        """批量优化低效实例"""
        efficiencies = []
        for inst_id in current_set:
            cov = self.monitor.get_instance_coverage(inst_id)
            weight = self.pool.instances[inst_id]['weight']
            efficiencies.append( (inst_id, cov/(weight+1e-6)) )
        
        efficiencies.sort(key=lambda x: x[1])
        
        # 替换效率最低的N个实例
        for _ in range(num_changes):
            if not efficiencies:
                break
            
            worst_id = efficiencies.pop(0)[0]
            new_config = random.choice([
                c for c in self.args.config_pool 
                if c != self.pool.instances[worst_id]['current_config']
            ])
            self.pool.switch_config(worst_id, new_config)
        
        return current_set

    def _batch_random(self, current_set, num_changes):
        """批量随机调整"""
        candidates = random.sample(list(current_set), num_changes)
        for inst_id in candidates:
            new_config = random.choice(self.args.config_pool)
            self.pool.switch_config(inst_id, new_config)
        return current_set
class EnhancedSAScheduler:
    def __init__(self, pool, monitor, args):
        self.pool = pool
        self.monitor = monitor
        self.args = args
        self.temp = args.init_temp
        self.best_state = set()
        self.best_energy = float('inf')  # 初始化 best_energy
        self.stagnation = 0
        
        # 初始化所有实例
        for inst_id in self.pool.instances:
            cfg = random.choice(args.config_pool)
            self.pool.switch_config(inst_id, cfg)

    def _calculate_energy(self, active_set):
        """动态能量计算"""
        resource_cost = sum(
            self.pool.instances[i]['weight'] for i in active_set
        )
        coverage = self.monitor.get_merged_coverage(active_set)
        return (0.7 * resource_cost) - (0.3 * coverage)

    def _generate_candidate(self, current_set):
        """生成候选方案：动态配置切换"""
        new_set = current_set.copy()
        
        # 选择操作类型
        if random.random() < 0.7:  # 70%概率切换低效实例
            return self._optimize_by_efficiency(new_set)
        else:  # 30%概率随机探索
            return self._random_exploration(new_set)

    def _optimize_by_efficiency(self, current_set):
        """基于效率优化"""
        efficiencies = []
        for inst_id in current_set:
            cov = self.monitor.get_instance_coverage(inst_id)
            weight = self.pool.instances[inst_id]['weight']
            efficiencies.append( (inst_id, cov/(weight+1e-6)) )
        
        if efficiencies:
            # 替换效率最低的实例
            efficiencies.sort(key=lambda x: x[1])
            worst_id = efficiencies[0][0]
            new_config = random.choice([
                c for c in self.args.config_pool 
                if c != self.pool.instances[worst_id]['current_config']
            ])
            self.pool.switch_config(worst_id, new_config)
            current_set.remove(worst_id)
            current_set.add(worst_id)  # 保持集合不变，实际已切换配置
        return current_set

    def _random_exploration(self, current_set):
        """随机探索新配置"""
        inst_id = random.choice(list(current_set))
        new_config = random.choice(self.args.config_pool)
        self.pool.switch_config(inst_id, new_config)
        return current_set  # 集合不变，仅内部配置变化

    def step(self):
        current_active = set(i for i, inst in self.pool.instances.items() 
                            if inst['active'])
        candidate = self._generate_candidate(current_active)
        
        current_e = self._calculate_energy(current_active)
        candidate_e = self._calculate_energy(candidate)
        
        accept_prob = math.exp(-(candidate_e - current_e)/self.temp) \
            if candidate_e > current_e else 1.0
        
        if random.random() < accept_prob:
            # 应用新状态（实际已在_generate_candidate中切换）
            if candidate_e < self.best_energy:
                self.best_energy = candidate_e
                self.best_state = candidate
                self.stagnation = 0
            else:
                self.stagnation += 1

        # 降温
        self.temp = max(self.temp * self.args.cool_rate, self.args.min_temp)

# ====================== 主程序执行流程 ======================
def main():
    args = parse_args()
    
    # 自动调整参数
    if args.num_instances >= 32:
        args.interval = max(args.interval, 120)  # 降低调度频率
        args.max_stagnant = min(args.max_stagnant, 10)  # 更快重置
        
    pool = OptimizedResourcePool(args)
    monitor = AsyncCoverageMonitor(pool)
    scheduler = HighPerformanceSAScheduler(pool, monitor, args)
    pool = None
    
    try:
        print("\n" + "="*40)
        print(" 动态资源池调度系统 ".center(40, '='))
        print(f" 实例数量: {args.num_instances}")
        print(f" 可用配置: {', '.join([Path(p).name for p in args.config_pool])}")
        
        pool = ResourcePool(args)
        monitor = CoverageMonitor(pool)
        scheduler = EnhancedSAScheduler(pool, monitor, args)
        
        iteration = 0
        while True:
            iteration += 1
            print(f"\n--- 迭代 {iteration} [温度: {scheduler.temp:.2f}] ---")
            
            start_time = time.time()
            monitor.refresh()
            scheduler.step()
            
            # 获取当前状态
            active_set = [i for i, inst in pool.instances.items() if inst['active']]
            merged_cov = monitor.get_merged_coverage(active_set)
            
            print(f"总分支覆盖: {merged_cov}")
            print("实例状态:")
            for inst_id in active_set:
                inst = pool.instances[inst_id]
                print(f"  ▪ 实例{inst_id}: {Path(inst['current_config']).name} | " +
                      f"权重: {inst['weight']:.1f} | " +
                      f"覆盖: {monitor.get_instance_coverage(inst_id)}")
            
            if scheduler.stagnation >= args.max_stagnant:
                print(f"\n⚠️ 连续{args.max_stagnant}次未改进，重置温度")
                scheduler.temp = args.init_temp
                scheduler.stagnation = 0
            
            time.sleep(args.interval)
    
    except KeyboardInterrupt:
        print("\n🛑 用户中断...")
    except Exception as e:
        print(f"\n[CRITICAL] 发生错误: {str(e)}")
    finally:
        if pool:
            print("\n" + "="*40)
            print(" 清理资源 ".center(40, '='))
            pool.cleanup()
        print("="*40 + "\n")

if __name__ == "__main__":
    main()
