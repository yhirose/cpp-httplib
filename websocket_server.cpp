#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>

std::queue<std::string> log_queue;
std::mutex log_mutex;
std::condition_variable log_cv;
bool logging_thread_running = true;

void log_thread_function() {
    while (logging_thread_running) {
        std::unique_lock<std::mutex> lock(log_mutex);
        log_cv.wait(lock, []{ return !log_queue.empty(); });
        
        while (!log_queue.empty()) {
            std::cout << log_queue.front() << std::endl;
            log_queue.pop();
        }
    }
}

// In your main function:
std::thread logger_thread(log_thread_function);

// In your handle_websocket_message function:
while (true) {
    auto message = websocket.read();
    {
        std::lock_guard<std::mutex> lock(log_mutex);
        log_queue.push("Received message: " + message);
    }
    log_cv.notify_one();
    process_message(message);
}

// Cleanup at program exit:
logging_thread_running = false;
log_cv.notify_all();
logger_thread.join();