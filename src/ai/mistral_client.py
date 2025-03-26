"""
Mistral AI integration for CVE analysis
"""
from mistralai import Mistral
from mistralai.models.chat_completion import ChatMessage
import os

class MistralAI:
    def __init__(self):
        self.client = Mistral(api_key=os.getenv('MISTRAL_API_KEY'))
        
    def analyze_vulnerabilities(self, port_data):
        """Analyze vulnerabilities using Mistral AI"""
        prompt = self._create_analysis_prompt(port_data)
        
        messages = [
            ChatMessage(role="user", content=prompt)
        ]
        
        chat_response = self.client.chat.complete(
            model="mistral-large-latest",
            messages=messages
        )
        
        return chat_response.choices[0].message.content
    
    def _create_analysis_prompt(self, port_data):
        """Create prompt for vulnerability analysis"""
        return f"""
        Analyze the security implications of the following open ports:
        {port_data}
        
        Provide:
        1. Known vulnerabilities
        2. Recent CVEs
        3. Security recommendations
        """