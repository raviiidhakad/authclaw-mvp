"use client";

import { useState, useRef, useEffect } from 'react';
import { Bot, Send, User, Loader2 } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { apiClient } from '@/lib/api-client';
import { toast } from 'sonner';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

type Message = {
  role: 'user' | 'assistant' | 'system';
  content: string;
};

export default function AgentPage() {
  const [messages, setMessages] = useState<Message[]>([
    { role: 'assistant', content: 'Hello! I am your AuthClaw Compliance Assistant. Ask me about policy violations, compliance scores, or audit logs.' }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Load from local storage on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem('authclaw_agent_chat_history');
      if (saved) {
        setMessages(JSON.parse(saved));
      }
    } catch (e) {
      console.error('Failed to load chat history', e);
    }
  }, []);

  // Save to local storage whenever messages change
  useEffect(() => {
    try {
      // Don't save if it's just the default initial message
      if (messages.length > 1) {
        localStorage.setItem('authclaw_agent_chat_history', JSON.stringify(messages));
      }
    } catch (e) {
      console.error('Failed to save chat history', e);
    }
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = { role: 'user', content: input };
    const newMessages = [...messages, userMessage];
    setMessages(newMessages);
    setInput('');
    setIsLoading(true);

    try {
      // Create payload without the initial welcome message, only real history
      const payloadMessages = newMessages.filter(m => m.content !== 'Hello! I am your AuthClaw Compliance Assistant. Ask me about policy violations, compliance scores, or audit logs.');
      
      const response = await apiClient.post('/agent/chat', { messages: payloadMessages });
      
      if (response.data && response.data.status === 'success') {
        const reply = response.data.data;
        setMessages([...newMessages, reply]);
      } else {
        throw new Error('Invalid response from agent');
      }
    } catch (error: any) {
      toast.error('Failed to communicate with agent');
      setMessages([...newMessages, { role: 'assistant', content: 'Sorry, I encountered an error. Please try again.' }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleSend();
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-10rem)]">
      <div className="mb-4">
        <h2 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Bot className="w-6 h-6 text-purple-500" />
          Agent Assistant
        </h2>
        <p className="text-neutral-400">Ask questions about your compliance posture, violations, and logs.</p>
      </div>

      <Card className="flex-1 flex flex-col overflow-hidden bg-neutral-900 border-neutral-800">
        <CardContent className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((message, i) => (
            <div key={i} className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`flex max-w-[80%] rounded-xl p-4 gap-3 ${message.role === 'user' ? 'bg-blue-600 text-white ml-12' : 'bg-neutral-950 border border-neutral-800 text-neutral-200 mr-12'}`}>
                {message.role === 'assistant' && (
                  <div className="mt-1 shrink-0">
                    <Bot className="w-5 h-5 text-purple-500" />
                  </div>
                )}
                
                <div className="prose prose-sm prose-invert max-w-none w-full">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {message.content}
                  </ReactMarkdown>
                </div>

                {message.role === 'user' && (
                  <div className="mt-1 shrink-0">
                    <User className="w-5 h-5 text-white/70" />
                  </div>
                )}
              </div>
            </div>
          ))}
          {isLoading && (
            <div className="flex justify-start">
              <div className="flex items-center rounded-xl p-4 gap-3 bg-neutral-950 border border-neutral-800 text-neutral-400">
                <Bot className="w-5 h-5 text-purple-500 animate-pulse" />
                <div className="flex space-x-1 items-center h-5">
                  <div className="w-2 h-2 bg-neutral-600 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
                  <div className="w-2 h-2 bg-neutral-600 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
                  <div className="w-2 h-2 bg-neutral-600 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
                </div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </CardContent>
        
        <div className="p-4 bg-neutral-950 border-t border-neutral-800 mt-auto">
          <div className="flex gap-2">
            <Input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask about policy violations, audit logs..."
              className="bg-neutral-900 border-neutral-800 text-neutral-100 flex-1"
              disabled={isLoading}
            />
            <Button onClick={handleSend} disabled={isLoading || !input.trim()} className="bg-purple-600 hover:bg-purple-700">
              {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
