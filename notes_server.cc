#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <atomic>
#include "httplib.h"

// 笔记结构体
struct Note {
    int id;
    std::string title;
    std::string content;
};

// 内存存储
std::unordered_map<int, Note> notes_store;
std::atomic<int> next_id{1};
std::mutex store_mutex;

// JSON 序列化单个笔记
std::string note_to_json(const Note& note) {
    return "{\"id\":" + std::to_string(note.id) + 
           ",\"title\":\"" + note.title + 
           "\",\"content\":\"" + note.content + "\"}";
}

// JSON 序列化笔记列表
std::string notes_to_json(const std::vector<Note>& notes) {
    std::string result = "[";
    for (size_t i = 0; i < notes.size(); ++i) {
        if (i > 0) result += ",";
        result += note_to_json(notes[i]);
    }
    result += "]";
    return result;
}

// 简单的 JSON 解析函数，提取字符串值
std::string extract_json_string(const std::string& json, const std::string& key) {
    std::string key_pattern = "\"" + key + "\":";
    size_t pos = json.find(key_pattern);
    if (pos == std::string::npos) return "";
    
    pos += key_pattern.length();
    // 跳过空白字符
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r')) {
        pos++;
    }
    
    if (pos >= json.length() || json[pos] != '"') return "";
    pos++; // 跳过开头的引号
    
    size_t end_pos = pos;
    while (end_pos < json.length() && json[end_pos] != '"') {
        // 处理转义字符
        if (json[end_pos] == '\\' && end_pos + 1 < json.length()) {
            end_pos += 2;
        } else {
            end_pos++;
        }
    }
    
    if (end_pos >= json.length()) return "";
    return json.substr(pos, end_pos - pos);
}

int main() {
    using namespace httplib;

    Server svr;

    // 设置 CORS 头，方便前端调用
    svr.set_default_headers({
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type"}
    });

    // 处理 OPTIONS 请求
    svr.Options("/notes", [](const Request& req, Response& res) {
        res.status = 200;
    });

    svr.Options(R"(/notes/(\d+))", [](const Request& req, Response& res) {
        res.status = 200;
    });

    // POST /notes - 新增笔记
    svr.Post("/notes", [](const Request& req, Response& res) {
        std::lock_guard<std::mutex> lock(store_mutex);
        
        // 检查 Content-Type
        if (!req.has_header("Content-Type") || 
            req.get_header_value("Content-Type").find("application/json") == std::string::npos) {
            res.status = 415; // Unsupported Media Type
            res.set_content("{\"error\":\"Content-Type must be application/json\"}", "application/json");
            return;
        }

        // 解析 JSON
        std::string title = extract_json_string(req.body, "title");
        std::string content = extract_json_string(req.body, "content");

        // 检查参数是否缺失
        if (title.empty() || content.empty()) {
            res.status = 400; // Bad Request
            res.set_content("{\"error\":\"Missing required fields: title and content are required\"}", "application/json");
            return;
        }

        // 创建新笔记
        int id = next_id++;
        Note new_note{id, title, content};
        notes_store[id] = new_note;

        // 返回创建的笔记
        res.status = 201; // Created
        res.set_content(note_to_json(new_note), "application/json");
    });

    // GET /notes - 获取全部笔记
    svr.Get("/notes", [](const Request& req, Response& res) {
        std::lock_guard<std::mutex> lock(store_mutex);
        
        std::vector<Note> notes;
        for (const auto& pair : notes_store) {
            notes.push_back(pair.second);
        }

        res.status = 200;
        res.set_content(notes_to_json(notes), "application/json");
    });

    // PUT /notes/{id} - 修改笔记
    svr.Put(R"(/notes/(\d+))", [](const Request& req, Response& res) {
        std::lock_guard<std::mutex> lock(store_mutex);
        
        int id = std::stoi(req.matches[1]);

        // 检查笔记是否存在
        if (notes_store.find(id) == notes_store.end()) {
            res.status = 404; // Not Found
            res.set_content("{\"error\":\"Note not found\"}", "application/json");
            return;
        }

        // 检查 Content-Type
        if (!req.has_header("Content-Type") || 
            req.get_header_value("Content-Type").find("application/json") == std::string::npos) {
            res.status = 415; // Unsupported Media Type
            res.set_content("{\"error\":\"Content-Type must be application/json\"}", "application/json");
            return;
        }

        // 解析 JSON
        std::string title = extract_json_string(req.body, "title");
        std::string content = extract_json_string(req.body, "content");

        // 检查参数是否缺失
        if (title.empty() || content.empty()) {
            res.status = 400; // Bad Request
            res.set_content("{\"error\":\"Missing required fields: title and content are required\"}", "application/json");
            return;
        }

        // 更新笔记
        notes_store[id].title = title;
        notes_store[id].content = content;

        // 返回更新后的笔记
        res.status = 200;
        res.set_content(note_to_json(notes_store[id]), "application/json");
    });

    // DELETE /notes/{id} - 删除笔记
    svr.Delete(R"(/notes/(\d+))", [](const Request& req, Response& res) {
        std::lock_guard<std::mutex> lock(store_mutex);
        
        int id = std::stoi(req.matches[1]);

        // 检查笔记是否存在
        if (notes_store.find(id) == notes_store.end()) {
            res.status = 404; // Not Found
            res.set_content("{\"error\":\"Note not found\"}", "application/json");
            return;
        }

        // 删除笔记
        notes_store.erase(id);

        res.status = 204; // No Content
    });

    // 启动服务器
    std::cout << "笔记服务已启动，监听端口 8080" << std::endl;
    std::cout << "API 接口：" << std::endl;
    std::cout << "  POST   /notes     - 新增笔记" << std::endl;
    std::cout << "  GET    /notes     - 获取全部笔记" << std::endl;
    std::cout << "  PUT    /notes/{id} - 修改笔记" << std::endl;
    std::cout << "  DELETE /notes/{id} - 删除笔记" << std::endl;
    std::cout << "按 Ctrl+C 停止服务" << std::endl;

    svr.listen("0.0.0.0", 8080);

    return 0;
}
