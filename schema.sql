create table if not exists foursquare_users (
    id serial primary key,
    foursquare_id text unique,
    token text,
    phone text,
    confirmed boolean default false,
    code text
)
