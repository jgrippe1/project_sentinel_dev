
import json
import logging
import requests
from sentinel.datastore import Datastore
from sentinel.version_utils import analyze_version_safety

logger = logging.getLogger("HybridAnalyzer")


PROVIDER_DEFAULTS = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-3.5-turbo"
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "model": "claude-3-haiku-20240307"
    },
    "google": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-1.5-flash"
    },
    "ollama": {
        "base_url": "http://homeassistant.local:11434/v1",
        "model": "llama3"
    },
    "custom": {
        "base_url": "",
        "model": ""
    }
}

class HybridAnalyzer:
    def __init__(self, config):
        self.config = config
        self.db = Datastore()
        options = config.get('options', {})
        
        self.llm_enabled = options.get('llm_enabled', False)
        # Robustly handle provider input (lowercase, strip spaces)
        raw_provider = options.get('llm_provider', 'openai')
        self.llm_provider = str(raw_provider).lower().strip() if raw_provider else 'openai'
        
        self.llm_api_key = options.get('llm_api_key', '')
        
        # Load Defaults based on Provider
        defaults = PROVIDER_DEFAULTS.get(self.llm_provider, PROVIDER_DEFAULTS['openai'])
        
        # User config overrides default if present
        self.llm_model = options.get('llm_model') or defaults['model']
        self.llm_base_url = options.get('llm_base_url') or defaults['base_url']
        
        # Clean URL (remove trailing slash)
        if self.llm_base_url and self.llm_base_url.endswith('/'):
            self.llm_base_url = self.llm_base_url[:-1]

    def analyze(self, cve_id, cve_description, asset_context):
        """
        Orchestrates the analysis: Cache -> Regex -> LLM -> Fail Open.
        Returns dict: {result: 'SAFE'|'VULNERABLE', reason: str, method: str}
        """
        actual_ver = asset_context.get('actual_fw_version')
        if not actual_ver:
            return {"result": "VULNERABLE", "reason": "No actual firmware version verified", "method": "default"}

        vendor = asset_context.get('vendor')
        model = asset_context.get('model')

        # 1. Check Cache
        cached = self.db.get_verification_result(cve_id, actual_ver, vendor, model)
        if cached:
            logger.info(f"Cache Hit for {cve_id}: {cached['analysis_result']}")
            return {
                "result": cached['analysis_result'],
                "reason": cached['reasoning'],
                "method": cached['method']
            }

        # 2. Regex Heuristic
        regex_result = analyze_version_safety(actual_ver, cve_description, asset_context)
        
        # High confidence threshold for regex
        if regex_result['confidence'] >= 80:
            logger.info(f"Regex High Confidence for {cve_id}: {regex_result['result']}")
            self.db.save_verification_result(
                cve_id, actual_ver, vendor, model,
                regex_result['result'], regex_result['confidence'],
                regex_result['method'], regex_result['reason']
            )
            return regex_result

        # 3. LLM Fallback
        if self.llm_enabled and self.llm_api_key:
            logger.info(f"Regex Low Confidence ({regex_result['confidence']}). Falling back to LLM for {cve_id}...")
            llm_result = self._query_llm(cve_id, cve_description, asset_context, regex_result)
            if llm_result:
                self.db.save_verification_result(
                    cve_id, actual_ver, vendor, model,
                    llm_result['result'], llm_result['confidence'],
                    llm_result['method'], llm_result['reason']
                )
                return llm_result
        
        # 4. Fail Open (Default to Vulnerable if unsure)
        return {
            "result": "VULNERABLE", 
            "reason": f"Heuristic inconclusive (Confidence {regex_result['confidence']}) and LLM unavailable/failed.",
            "method": "fail-open"
        }

    def _query_llm(self, cve_id, cve_description, asset_context, regex_context):
        prompt = f"""
        You are a cybersecurity analyst. Analyze if the following asset is vulnerable to the CVE.
        
        ASSET:
        - Vendor: {asset_context.get('vendor')}
        - Model: {asset_context.get('model')}
        - Firmware Version: {asset_context.get('actual_fw_version')}
        
        CVE:
        - ID: {cve_id}
        - Description: {cve_description}
        
        REGEX ANALYSIS (Internal Tool):
        - Result: {regex_context['result']}
        - Reason: {regex_context['reason']}
        
        TASK:
        Is the asset version SAFE or VULNERABLE? 
        If the CVE description doesn't apply to this specific vendor/product, mark as SAFE.
        If the version is strictly NEWER than the fixed version, mark as SAFE.
        
        RESPONSE FORMAT (JSON ONLY):
        {{
            "result": "SAFE" | "VULNERABLE",
            "confidence": <0-100 integer>,
            "reason": "<short explanation>"
        }}
        """
        
        try:
            # Special Handling for Anthropic
            if self.llm_provider == 'anthropic':
                return self._query_anthropic(prompt)

            # Standard OpenAI Compatible (OpenAI, Google, Ollama, etc.)
            headers = {
                "Authorization": f"Bearer {self.llm_api_key}",
                "Content-Type": "application/json"
            }
            data = {
                "model": self.llm_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1
            }
            
            url = f"{self.llm_base_url}/chat/completions"
            response = requests.post(url, headers=headers, json=data, timeout=15)
            
            return self._parse_llm_response(response, f"llm-{self.llm_provider}")
            
        except Exception as e:
            logger.error(f"LLM Exception: {e}")
            return None

    def _query_anthropic(self, prompt):
        """Specific handler for Anthropic API."""
        try:
            headers = {
                "x-api-key": self.llm_api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            }
            data = {
                "model": self.llm_model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024,
                "temperature": 0.1
            }
            url = f"{self.llm_base_url}/messages"
            response = requests.post(url, headers=headers, json=data, timeout=15)
            
            if response.status_code == 200:
                content = response.json()['content'][0]['text']
                return self._parse_content(content, "llm-anthropic")
            else:
                logger.error(f"Anthropic API Error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Anthropic Exception: {e}")
            return None

    def _parse_llm_response(self, response, method_name):
        if response.status_code == 200:
            resp_json = response.json()
            content = resp_json['choices'][0]['message']['content']
            return self._parse_content(content, method_name)
        else:
            logger.error(f"LLM API Error: {response.status_code} - {response.text}")
            return None

    def _parse_content(self, content, method_name):
        try:
            # Clean code blocks if present
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].strip()
                
            parsed = json.loads(content)
            return {
                "result": parsed.get("result", "VULNERABLE").upper(),
                "confidence": parsed.get("confidence", 50),
                "reason": parsed.get("reason", "LLM Analysis"),
                "method": method_name
            }
        except Exception as e:
            logger.error(f"Failed to parse LLM JSON: {e}. Content: {content}")
            return None
