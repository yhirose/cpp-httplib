// ThreadPool unit tests
// Set a short idle timeout for faster shrink tests
#define CPPHTTPLIB_THREAD_POOL_IDLE_TIMEOUT 1

#include <httplib.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

using namespace httplib;

TEST(ThreadPoolTest, BasicTaskExecution) {
  ThreadPool pool(4);
  std::atomic<int> count(0);

  for (int i = 0; i < 10; i++) {
    pool.enqueue([&count]() { count++; });
  }

  pool.shutdown();
  EXPECT_EQ(10, count.load());
}

TEST(ThreadPoolTest, FixedPoolWhenMaxEqualsBase) {
  // max_n == 0 means max = base (fixed pool behavior)
  ThreadPool pool(4);
  std::atomic<int> count(0);

  for (int i = 0; i < 100; i++) {
    pool.enqueue([&count]() { count++; });
  }

  pool.shutdown();
  EXPECT_EQ(100, count.load());
}

TEST(ThreadPoolTest, DynamicScaleUp) {
  // base=2, max=8: block 2 base threads, then enqueue more tasks
  ThreadPool pool(2, 8);

  std::atomic<int> active(0);
  std::atomic<int> max_active(0);
  std::atomic<int> completed(0);
  std::mutex barrier_mutex;
  std::condition_variable barrier_cv;
  bool release = false;

  // Occupy all base threads with blocking tasks
  for (int i = 0; i < 2; i++) {
    pool.enqueue([&]() {
      active++;
      {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        barrier_cv.wait(lock, [&] { return release; });
      }
      active--;
      completed++;
    });
  }

  // Wait for base threads to be occupied
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // These should trigger dynamic thread creation
  for (int i = 0; i < 4; i++) {
    pool.enqueue([&]() {
      int cur = ++active;
      // Track peak active count
      int prev = max_active.load();
      while (cur > prev && !max_active.compare_exchange_weak(prev, cur)) {}
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      active--;
      completed++;
    });
  }

  // Wait for dynamic tasks to complete
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  // Release the blocking tasks
  {
    std::unique_lock<std::mutex> lock(barrier_mutex);
    release = true;
  }
  barrier_cv.notify_all();

  pool.shutdown();
  EXPECT_EQ(6, completed.load());
  // More than 2 threads were active simultaneously
  EXPECT_GT(max_active.load(), 2);
}

TEST(ThreadPoolTest, DynamicShrinkAfterIdle) {
  // CPPHTTPLIB_THREAD_POOL_IDLE_TIMEOUT is set to 1 second
  ThreadPool pool(2, 8);

  std::atomic<int> completed(0);

  // Enqueue tasks that require dynamic threads
  for (int i = 0; i < 8; i++) {
    pool.enqueue([&]() {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      completed++;
    });
  }

  // Wait for all tasks to complete + idle timeout + margin
  std::this_thread::sleep_for(std::chrono::milliseconds(2500));

  // Now enqueue a simple task to verify the pool still works
  // (base threads are still alive)
  std::atomic<bool> final_task_done(false);
  pool.enqueue([&]() { final_task_done = true; });

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  pool.shutdown();
  EXPECT_EQ(8, completed.load());
  EXPECT_TRUE(final_task_done.load());
}

TEST(ThreadPoolTest, ShutdownWithActiveDynamicThreads) {
  ThreadPool pool(2, 8);

  std::atomic<int> started(0);

  std::mutex block_mutex;
  std::condition_variable block_cv;
  bool release = false;

  // Start tasks on dynamic threads that block until released
  for (int i = 0; i < 6; i++) {
    pool.enqueue([&]() {
      started++;
      std::unique_lock<std::mutex> lock(block_mutex);
      block_cv.wait(lock, [&] { return release; });
    });
  }

  // Wait for tasks to start
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  EXPECT_GE(started.load(), 2);

  // Release all blocked threads, then shutdown
  {
    std::unique_lock<std::mutex> lock(block_mutex);
    release = true;
  }
  block_cv.notify_all();

  pool.shutdown();
}

TEST(ThreadPoolTest, MaxQueuedRequests) {
  // base=2, max=2 (fixed), mqr=3
  ThreadPool pool(2, 2, 3);

  std::mutex block_mutex;
  std::condition_variable block_cv;
  bool release = false;

  // Block both threads
  for (int i = 0; i < 2; i++) {
    EXPECT_TRUE(pool.enqueue([&]() {
      std::unique_lock<std::mutex> lock(block_mutex);
      block_cv.wait(lock, [&] { return release; });
    }));
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Fill the queue up to max_queued_requests
  EXPECT_TRUE(pool.enqueue([]() {}));
  EXPECT_TRUE(pool.enqueue([]() {}));
  EXPECT_TRUE(pool.enqueue([]() {}));

  // This should fail - queue is full
  EXPECT_FALSE(pool.enqueue([]() {}));

  // Release blocked threads
  {
    std::unique_lock<std::mutex> lock(block_mutex);
    release = true;
  }
  block_cv.notify_all();

  pool.shutdown();
}

#ifndef CPPHTTPLIB_NO_EXCEPTIONS
TEST(ThreadPoolTest, InvalidMaxThreadsThrows) {
  // max_n < n should throw
  EXPECT_THROW(ThreadPool(8, 4), std::invalid_argument);
}
#endif

TEST(ThreadPoolTest, EnqueueAfterShutdownReturnsFalse) {
  ThreadPool pool(2);
  pool.shutdown();
  EXPECT_FALSE(pool.enqueue([]() {}));
}

TEST(ThreadPoolTest, ConcurrentEnqueue) {
  ThreadPool pool(4, 16);
  std::atomic<int> count(0);
  const int num_producers = 4;
  const int tasks_per_producer = 100;

  std::vector<std::thread> producers;
  for (int p = 0; p < num_producers; p++) {
    producers.emplace_back([&]() {
      for (int i = 0; i < tasks_per_producer; i++) {
        pool.enqueue([&count]() { count++; });
      }
    });
  }

  for (auto &t : producers) {
    t.join();
  }

  pool.shutdown();
  EXPECT_EQ(num_producers * tasks_per_producer, count.load());
}
