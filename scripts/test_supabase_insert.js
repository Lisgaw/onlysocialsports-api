'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

async function test() {
  // Get admin user id first
  const { data: users } = await supabase.from('users').select('id').eq('email', 'admin@sporpartner.com').single();
  console.log('Admin:', users?.id);

  // Try insert via Supabase client (same as backend uses)
  const { data, error } = await supabase
    .from('posts')
    .insert({
      id: 'post_supatest_' + Date.now(),
      user_id: users.id,
      post_type: 'SOCIAL_LISTING',
      content: 'Supabase client test',
      title: 'Test title',
      sport_id: 'basketball',
      sport_name: 'Basketbol',
      country_name: null,
      city_id: null,
      city_name: null,
      district_id: null,
      district_name: null,
      updated_at: new Date().toISOString(),
    })
    .select()
    .single();

  if (error) {
    console.log('Supabase insert FAILED:', error.message, error.code, error.details);
  } else {
    console.log('Supabase insert OK:', JSON.stringify(data, null, 2));
    // Clean up
    await supabase.from('posts').delete().eq('id', data.id);
    console.log('Cleaned up');
  }
}

test().catch(e => console.error('Fatal:', e.message));
