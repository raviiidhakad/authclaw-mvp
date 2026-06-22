DO $$ 
DECLARE 
    v_user_id uuid; 
    v_tenant_id uuid;
    v_role_owner_id uuid;
    v_role_admin_id uuid;
BEGIN 
    SELECT id, tenant_id INTO v_user_id, v_tenant_id FROM users WHERE email = 'root.test1@gmail.com';
    
    INSERT INTO roles (name, description, is_system) VALUES ('owner', 'Organization Owner', true) ON CONFLICT (name) DO NOTHING;
    INSERT INTO roles (name, description, is_system) VALUES ('admin', 'Organization Administrator', true) ON CONFLICT (name) DO NOTHING;
    
    SELECT id INTO v_role_owner_id FROM roles WHERE name = 'owner';
    SELECT id INTO v_role_admin_id FROM roles WHERE name = 'admin';

    IF v_user_id IS NOT NULL THEN
        INSERT INTO user_roles (user_id, role_id, tenant_id) VALUES (v_user_id, v_role_owner_id, v_tenant_id) ON CONFLICT DO NOTHING;
        INSERT INTO user_roles (user_id, role_id, tenant_id) VALUES (v_user_id, v_role_admin_id, v_tenant_id) ON CONFLICT DO NOTHING;
    END IF;
END $$;
