import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { 
  LayoutDashboard, 
  Network, 
  ShieldCheck, 
  Activity, 
  Settings,
  AlertTriangle
} from 'lucide-react';
import { useAuth } from '@/hooks/use-auth';

const NAV_ITEMS = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Gateway', href: '/gateway', icon: Network },
  { name: 'Policies', href: '/policies', icon: ShieldCheck },
  { name: 'Violations', href: '/policies/violations', icon: AlertTriangle },
  { name: 'Compliance', href: '/compliance', icon: ShieldCheck },
  { name: 'Audit Logs', href: '/audit', icon: Activity },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { user } = useAuth();

  return (
    <div className="w-64 border-r border-neutral-800 bg-neutral-950 flex flex-col h-screen fixed left-0 top-0">
      <div className="h-16 flex items-center px-6 border-b border-neutral-800">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center">
            <span className="text-white font-bold text-sm">AC</span>
          </div>
          <span className="font-bold text-lg text-white">AuthClaw</span>
        </div>
      </div>
      
      <div className="flex-1 py-6 flex flex-col gap-1 px-4">
        {NAV_ITEMS.map((item) => {
          const isActive = pathname === item.href || (pathname?.startsWith(item.href) && item.href !== '/');
          
          return (
            <Link 
              key={item.href} 
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                isActive 
                  ? 'bg-blue-600/10 text-blue-500' 
                  : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900'
              }`}
            >
              <item.icon className="w-4 h-4" />
              {item.name}
            </Link>
          );
        })}
      </div>

      <div className="p-4 border-t border-neutral-800">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-neutral-800 flex items-center justify-center text-xs font-medium text-neutral-300 uppercase">
            {user?.first_name?.[0] || ''}{user?.last_name?.[0] || ''}
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-medium text-neutral-200">{user?.first_name} {user?.last_name}</span>
            <span className="text-xs text-neutral-500 truncate w-40">{user?.email}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
