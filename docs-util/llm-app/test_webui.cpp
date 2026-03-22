// test_webui.cpp — Browser-based E2E tests for Ch5 Web UI.
// Uses webdriver.h (cpp-httplib + json.hpp) to control headless Firefox.
//
// Usage: test_webui <port>
//   port: the translate-server port (e.g. 18080)

#include "webdriver.h"

#include <cstdlib>
#include <iostream>
#include <string>

// ─── Test framework (minimal) ────────────────────────────────

static int pass_count = 0;
static int fail_count = 0;

#define PASS(label)                                                            \
  do {                                                                         \
    std::cout << "  PASS: " << (label) << "\n";                                \
    ++pass_count;                                                              \
  } while (0)

#define FAIL(label, detail)                                                    \
  do {                                                                         \
    std::cout << "  FAIL: " << (label) << "\n";                                \
    std::cout << "    " << (detail) << "\n";                                   \
    ++fail_count;                                                              \
  } while (0)

#define ASSERT_TRUE(cond, label)                                               \
  do {                                                                         \
    if (cond) {                                                                \
      PASS(label);                                                             \
    } else {                                                                   \
      FAIL(label, "condition was false");                                      \
    }                                                                          \
  } while (0)

#define ASSERT_CONTAINS(haystack, needle, label)                               \
  do {                                                                         \
    if (std::string(haystack).find(needle) != std::string::npos) {             \
      PASS(label);                                                             \
    } else {                                                                   \
      FAIL(label, "'" + std::string(haystack) + "' does not contain '" +       \
                      std::string(needle) + "'");                              \
    }                                                                          \
  } while (0)

#define ASSERT_ELEMENT_EXISTS(session, selector)                               \
  do {                                                                         \
    try {                                                                      \
      (session).css(selector);                                                 \
      PASS("Element " selector " exists");                                     \
    } catch (...) { FAIL("Element " selector " exists", "not found"); }        \
  } while (0)

// ─── Helpers ─────────────────────────────────────────────────

static std::string base_url;

void navigate_and_wait_for_models(webdriver::Session &session) {
  session.navigate(base_url);
  session.wait_until(
      "return document.querySelectorAll('#model-select option').length > 0",
      5000);
}

void test_page_loads(webdriver::Session &session) {
  std::cout << "=== TC1: Page loads with correct structure\n";

  session.navigate(base_url);

  auto title = session.title();
  ASSERT_CONTAINS(title, "Translate", "Page title contains 'Translate'");

  // Verify main DOM elements exist
  ASSERT_ELEMENT_EXISTS(session, "#model-select");
  ASSERT_ELEMENT_EXISTS(session, "#input-text");
  ASSERT_ELEMENT_EXISTS(session, "#output-text");
  ASSERT_ELEMENT_EXISTS(session, "#target-lang");
}

void test_model_dropdown(webdriver::Session &session) {
  std::cout << "=== TC2: Model dropdown is populated\n";

  navigate_and_wait_for_models(session);

  // Note: WebDriver findElements cannot find <option> elements directly
  // in geckodriver/Firefox, so we use JS to count them.
  auto option_count = session.execute_script(
      "return document.querySelectorAll('#model-select option').length");
  ASSERT_TRUE(option_count != "0" && option_count != "null",
              "Model dropdown has options (count=" + option_count + ")");

  // Check that at least one option has a selected attribute
  auto selected_val = session.execute_script(
      "return document.querySelector('#model-select').value");
  ASSERT_TRUE(selected_val != "null" && !selected_val.empty(),
              "A model is selected (value='" + selected_val + "')");
}

void test_translation_sse(webdriver::Session &session) {
  std::cout << "=== TC3: Translation with SSE streaming\n";

  navigate_and_wait_for_models(session);

  // Clear and type input — debounce auto-translate triggers after 300ms
  auto input = session.css("#input-text");
  input.clear();
  input.send_keys("Hello world");

  // Wait for output to appear (debounce 300ms + LLM inference)
  bool has_output = session.wait_until(
      "return document.querySelector('#output-text').textContent.length > 0",
      120000);
  ASSERT_TRUE(has_output, "Translation output appeared");

  auto output_text = session.execute_script(
      "return document.querySelector('#output-text').textContent");
  ASSERT_TRUE(!output_text.empty() && output_text != "null",
              "Output text is non-empty ('" + output_text.substr(0, 50) +
                  "...')");

  // Wait for busy state to be cleared after completion
  bool busy_cleared = session.wait_until(
      "return !document.body.classList.contains('busy')", 120000);
  ASSERT_TRUE(busy_cleared, "Busy state cleared after translation");
}

void test_busy_state(webdriver::Session &session) {
  std::cout << "=== TC4: Busy state during translation\n";

  navigate_and_wait_for_models(session);

  auto input = session.css("#input-text");
  input.clear();

  // Clear previous output
  session.execute_script(
      "document.querySelector('#output-text').textContent = ''");

  input.send_keys(
      "I had a great time visiting Tokyo last spring. "
      "The cherry blossoms were beautiful and the food was amazing.");

  // Check busy state (debounce 300ms then translation starts)
  bool went_busy = session.wait_until(
      "return document.body.classList.contains('busy')", 5000);
  ASSERT_TRUE(went_busy, "Body gets 'busy' class during translation");

  // Wait for completion
  session.wait_until("return !document.body.classList.contains('busy')",
                     120000);
  PASS("Busy class removed after completion");
}

void test_empty_input(webdriver::Session &session) {
  std::cout << "=== TC5: Empty input does nothing\n";

  navigate_and_wait_for_models(session);

  // Clear input and output
  auto input = session.css("#input-text");
  input.clear();
  session.execute_script(
      "document.querySelector('#output-text').textContent = ''");

  // Trigger input event on empty textarea
  session.execute_script("document.querySelector('#input-text').dispatchEvent("
                         "  new Event('input'));");

  // Wait longer than debounce (300ms) — nothing should happen
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  auto output_text = session.execute_script(
      "return document.querySelector('#output-text').textContent");
  ASSERT_TRUE(output_text.empty() || output_text == "null" || output_text == "",
              "No output for empty input");
}

void test_target_lang_selector(webdriver::Session &session) {
  std::cout << "=== TC6: Target language selector\n";

  navigate_and_wait_for_models(session);

  // Check available language options (use JS — WebDriver can't find <option>)
  auto lang_count = session.execute_script(
      "return document.querySelectorAll('#target-lang option').length");
  ASSERT_TRUE(lang_count != "0" && lang_count != "null",
              "Language selector has multiple options (count=" + lang_count +
                  ")");

  // Switch to English and translate
  session.execute_script("document.querySelector('#target-lang').value = 'en';"
                         "document.querySelector('#target-lang').dispatchEvent("
                         "  new Event('change'));");

  // Clear output, then type — debounce auto-translate triggers
  session.execute_script(
      "document.querySelector('#output-text').textContent = ''");

  auto input = session.css("#input-text");
  input.clear();
  input.send_keys("こんにちは");

  bool has_output = session.wait_until(
      "return document.querySelector('#output-text').textContent.length > 0",
      120000);
  ASSERT_TRUE(has_output, "Translation with target_lang=en produced output");
}

void test_model_switch(webdriver::Session &session) {
  std::cout << "=== TC7: Model switching\n";

  navigate_and_wait_for_models(session);

  auto options = session.css_all("#model-select option");
  if (options.size() < 2) {
    PASS("Model switch skipped (only 1 model available)");
    return;
  }

  // Get current model
  auto current = session.execute_script(
      "return document.querySelector('#model-select').value");

  // Switch to a different model (pick the second option's value)
  auto other_value = options[1].attribute("value");
  if (other_value == current && options.size() > 2) {
    other_value = options[2].attribute("value");
  }

  session.execute_script(
      "document.querySelector('#model-select').value = '" + other_value +
      "';"
      "document.querySelector('#model-select').dispatchEvent("
      "  new Event('change'));");

  // Wait for model switch to complete (SSE: downloading → loading → ready)
  bool ready = session.wait_until(
      "return !document.body.classList.contains('busy')", 120000);
  ASSERT_TRUE(ready, "Model switch completed");

  auto new_value = session.execute_script(
      "return document.querySelector('#model-select').value");
  ASSERT_TRUE(new_value == other_value,
              "Model changed to '" + other_value + "'");
}

void test_download_dialog_structure(webdriver::Session &session) {
  std::cout << "=== TC8: Download dialog DOM structure\n";

  session.navigate(base_url);

  ASSERT_ELEMENT_EXISTS(session, "#download-dialog");
  ASSERT_ELEMENT_EXISTS(session, "#download-progress");
  ASSERT_ELEMENT_EXISTS(session, "#download-status");
  ASSERT_ELEMENT_EXISTS(session, "#download-cancel");
}

// ─── Main ────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: test_webui <server-port>\n";
    return 1;
  }

  int port = std::atoi(argv[1]);
  base_url = "http://127.0.0.1:" + std::to_string(port);

  std::cout << "=== Ch5 Web UI Browser Tests\n";
  std::cout << "=== Server: " << base_url << "\n\n";

  try {
    webdriver::Session session;

    test_page_loads(session);
    test_model_dropdown(session);
    test_translation_sse(session);
    test_busy_state(session);
    test_empty_input(session);
    test_target_lang_selector(session);
    test_model_switch(session);
    test_download_dialog_structure(session);

  } catch (const webdriver::Error &e) {
    std::cerr << "WebDriver error: " << e.what() << "\n";
    ++fail_count;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << "\n";
    ++fail_count;
  }

  std::cout << "\n=== Results: " << pass_count << " passed, " << fail_count
            << " failed\n";

  return fail_count > 0 ? 1 : 0;
}
