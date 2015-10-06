package Isucon5::Web;
use 5.020;

use strict;
use warnings;
use utf8;
use Kossy;
use DBIx::Sunny;
use Encode;

my %users_by_id = ();
my %users_by_name = ();
my %users_by_email = ();
my %relations = ();
{
    my $db = dbh();

    for my $user (@{$db->select_all('SELECT id, account_name, nick_name, email, account_name AS password FROM users')}) {
        $users_by_id{$user->{id}} = $user;
        $users_by_name{$user->{account_name}} = $user;
        $users_by_email{$user->{email}} = $user;
    }

    for my $rel (@{$db->select_all('SELECT one, another FROM relations WHERE id <= 500000')}) {
        $relations{$rel->{one}} ||= {};
        $relations{$rel->{one}}{$rel->{another}} = 1;
    }
}

sub dbh {
    my %db = (
        host => $ENV{ISUCON5_DB_HOST} || 'localhost',
        port => $ENV{ISUCON5_DB_PORT} || 3306,
        username => $ENV{ISUCON5_DB_USER} || 'root',
        password => $ENV{ISUCON5_DB_PASSWORD},
        database => $ENV{ISUCON5_DB_NAME} || 'isucon5q',
    );
    DBIx::Sunny->connect(
        "dbi:mysql:database=$db{database};host=$db{host};port=$db{port}", $db{username}, $db{password}, {
            RaiseError => 1,
            PrintError => 0,
            AutoInactiveDestroy => 1,
            mysql_enable_utf8   => 1,
            mysql_auto_reconnect => 1,
        },
    );
}

my $db;
sub db {
    $db ||= dbh();
}

my ($SELF, $C);
sub session {
    $C->stash->{session};
}

sub stash {
    $C->stash;
}

sub redirect {
    $C->redirect(@_);
}

sub abort_authentication_error {
    session()->{user_id} = undef;
    $C->halt(401, encode_utf8($C->tx->render('login.tx', { message => 'ログインに失敗しました' })));
}

sub abort_permission_denied {
    $C->halt(403, encode_utf8($C->tx->render('error.tx', { message => '友人のみしかアクセスできません' })));
}

sub abort_content_not_found {
    $C->halt(404, encode_utf8($C->tx->render('error.tx', { message => '要求されたコンテンツは存在しません' })));
}

sub authenticate {
    my ($email, $password) = @_;
    my $result = $users_by_email{$email};
    if (!$result or $result->{password} ne $password) {
        abort_authentication_error();
    }
    session()->{user_id} = $result->{id};
    return $result;
}

sub current_user {
    my ($self, $c) = @_;
    my $user = stash()->{user};

    return $user if ($user);

    return undef if (!session()->{user_id});

    $user = $users_by_id{session()->{user_id}};
    if (!$user) {
        session()->{user_id} = undef;
        abort_authentication_error();
    }
    return $user;
}

sub set_user_names {
    my ($item, $user) = @_;
    $item->{account_name} = $user->{account_name};
    $item->{nick_name} = $user->{nick_name};
    $item;
}

sub get_user {
    my ($user_id) = @_;
    my $user = $users_by_id{$user_id};
    abort_content_not_found() if (!$user);
    return $user;
}

sub user_from_account {
    my ($account_name) = @_;
    my $user = $users_by_name{$account_name};
    abort_content_not_found() if (!$user);
    return $user;
}

sub is_friend {
    my ($another_id) = @_;
    my $user_id = session()->{user_id};
    return 1 if $relations{$user_id}{$another_id};
    my $query = 'SELECT COUNT(1) AS cnt FROM relations WHERE one = ? AND another = ?';
    my $cnt = db->select_one($query, $user_id, $another_id);
    return $cnt > 0 ? 1 : 0;
}

sub is_friend_account {
    my ($account_name) = @_;
    is_friend(user_from_account($account_name)->{id});
}

sub mark_footprint {
    my ($user_id) = @_;
    if ($user_id != current_user()->{id}) {
        my $query = 'REPLACE INTO footprints (user_id,owner_id,date) VALUES (?,?,NOW())';
        db->query($query, $user_id, current_user()->{id});
    }
}

sub permitted {
    my ($another_id) = @_;
    $another_id == current_user()->{id} || is_friend($another_id);
}

my $PREFS;
sub prefectures {
    $PREFS ||= do {
        [
        '未入力',
        '北海道', '青森県', '岩手県', '宮城県', '秋田県', '山形県', '福島県', '茨城県', '栃木県', '群馬県', '埼玉県', '千葉県', '東京都', '神奈川県', '新潟県', '富山県',
        '石川県', '福井県', '山梨県', '長野県', '岐阜県', '静岡県', '愛知県', '三重県', '滋賀県', '京都府', '大阪府', '兵庫県', '奈良県', '和歌山県', '鳥取県', '島根県',
        '岡山県', '広島県', '山口県', '徳島県', '香川県', '愛媛県', '高知県', '福岡県', '佐賀県', '長崎県', '熊本県', '大分県', '宮崎県', '鹿児島県', '沖縄県'
        ]
    };
}

filter 'authenticated' => sub {
    my ($app) = @_;
    sub {
        my ($self, $c) = @_;
        if (!current_user()) {
            return redirect('/login');
        }
        $app->($self, $c);
    }
};

filter 'set_global' => sub {
    my ($app) = @_;
    sub {
        my ($self, $c) = @_;
        $SELF = $self;
        $C = $c;
        $C->stash->{session} = $c->req->env->{"psgix.session"};
        $app->($self, $c);
    }
};

get '/login' => sub {
    my ($self, $c) = @_;
    $c->render('login.tx', { message => '高負荷に耐えられるSNSコミュニティサイトへようこそ!' });
};

post '/login' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    my $email = $c->req->param("email");
    my $password = $c->req->param("password");
    authenticate($email, $password);
    redirect('/');
};

get '/logout' => [qw(set_global)] => sub {
    my ($self, $c) = @_;
    session()->{user_id} = undef;
    redirect('/login');
};

get '/' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;

    my $profile = db->select_row('SELECT * FROM profiles WHERE user_id = ?', current_user()->{id});

    my $entries_query = "SELECT id, SUBSTRING_INDEX(body, '\n', 1) AS title FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5";
    my $entries = [];
    for my $entry (@{db->select_all($entries_query, current_user()->{id})}) {
        push @$entries, $entry;
    }

    my $comments_for_me_query = <<SQL;
SELECT c.id AS id, c.entry_id AS entry_id, c.user_id AS user_id, c.comment AS comment, c.created_at AS created_at
FROM comments c
JOIN entries e ON c.entry_id = e.id
WHERE e.user_id = ?
ORDER BY c.created_at DESC
LIMIT 10
SQL
    my $comments_for_me = [];
    for my $comment (@{db->select_all($comments_for_me_query, current_user()->{id})}) {
        push @$comments_for_me, set_user_names($comment, get_user($comment->{user_id}));
    }

    my $friend_ids = [];
    for my $rel (@{db->select_all('SELECT another FROM relations WHERE one = ?', current_user()->{id})}) {
        push @$friend_ids, $rel->{another};
    }

    my $entries_of_friends_query = <<SQL;
SELECT id, user_id, SUBSTRING_INDEX(body, '\n', 1) AS title, created_at
FROM entries
WHERE user_id IN (?)
ORDER BY id DESC
LIMIT 10
SQL
    my $entries_of_friends = [];
    for my $entry (@{db->select_all($entries_of_friends_query, $friend_ids)}) {
        push @$entries_of_friends, set_user_names($entry, get_user($entry->{user_id}));
    }

    my $comments_of_friends_query = <<SQL;
SELECT c.user_id AS user_id, c.comment AS comment, c.created_at AS created_at, e.user_id AS entry_user_id
FROM comments c
JOIN entries e ON c.entry_id = e.id
WHERE c.user_id IN (?)
AND (
  e.private = 0
  OR
  e.private = 1 AND (e.user_id = ? OR e.user_id IN (?))
)
ORDER BY c.id DESC
LIMIT 10
SQL
    my $comments_of_friends = [];
    for my $comment (@{db->select_all($comments_of_friends_query, $friend_ids, current_user()->{id}, $friend_ids)}) {
        $comment->{entry} = set_user_names(+{}, get_user($comment->{entry_user_id}));
        push @$comments_of_friends, set_user_names($comment, get_user($comment->{user_id}));
    }

    my $query = 'SELECT owner_id, created_at AS updated FROM footprints WHERE user_id = ? ORDER BY id DESC LIMIT 10';
    my $footprints = [];
    for my $fp (@{db->select_all($query, current_user()->{id})}) {
        push @$footprints, set_user_names($fp, get_user($fp->{owner_id}));
    }

    my $locals = {
        'user' => current_user(),
        'profile' => $profile,
        'entries' => $entries,
        'comments_for_me' => $comments_for_me,
        'entries_of_friends' => $entries_of_friends,
        'comments_of_friends' => $comments_of_friends,
        'footprints' => $footprints
    };
    $c->render('index.tx', $locals);
};

get '/profile/:account_name' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $account_name = $c->args->{account_name};
    my $owner = user_from_account($account_name);
    my $prof = db->select_row('SELECT * FROM profiles WHERE user_id = ?', $owner->{id});
    $prof = {} if (!$prof);
    my $query;
    if (permitted($owner->{id})) {
        $query = 'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5';
    } else {
        $query = 'SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at LIMIT 5';
    }
    my $entries = [];
    for my $entry (@{db->select_all($query, $owner->{id})}) {
        $entry->{is_private} = ($entry->{private} == 1);
        my ($title, $content) = split(/\n/, $entry->{body}, 2);
        $entry->{title} = $title;
        $entry->{content} = $content;
        push @$entries, $entry;
    }
    mark_footprint($owner->{id});
    my $locals = {
        owner => $owner,
        profile => $prof,
        entries => $entries,
        private => permitted($owner->{id}),
        is_friend => is_friend($owner->{id}),
        current_user => current_user(),
        prefectures => prefectures(),
    };
    $c->render('profile.tx', $locals);
};

post '/profile/:account_name' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $account_name = $c->args->{account_name};
    if ($account_name ne current_user()->{account_name}) {
        abort_permission_denied();
    }
    my $first_name =  $c->req->param('first_name');
    my $last_name = $c->req->param('last_name');
    my $sex = $c->req->param('sex');
    my $birthday = $c->req->param('birthday');
    my $pref = $c->req->param('pref');

    my $prof = db->select_row('SELECT * FROM profiles WHERE user_id = ?', current_user()->{id});
    if ($prof) {
      my $query = <<SQL;
UPDATE profiles
SET first_name=?, last_name=?, sex=?, birthday=?, pref=?, updated_at=CURRENT_TIMESTAMP()
WHERE user_id = ?
SQL
        db->query($query, $first_name, $last_name, $sex, $birthday, $pref, current_user()->{id});
    } else {
        my $query = <<SQL;
INSERT INTO profiles (user_id,first_name,last_name,sex,birthday,pref) VALUES (?,?,?,?,?,?)
SQL
        db->query($query, current_user()->{id}, $first_name, $last_name, $sex, $birthday, $pref);
    }
    redirect('/profile/'.$account_name);
};

get '/diary/entries/:account_name' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $account_name = $c->args->{account_name};
    my $owner = user_from_account($account_name);
    my $query;
    if (permitted($owner->{id})) {
        $query = 'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at DESC LIMIT 20';
    } else {
        $query = 'SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at DESC LIMIT 20';
    }
    my $entries = [];
    for my $entry (@{db->select_all($query, $owner->{id})}) {
        $entry->{is_private} = ($entry->{private} == 1);
        my ($title, $content) = split(/\n/, $entry->{body}, 2);
        $entry->{title} = $title;
        $entry->{content} = $content;
        $entry->{comment_count} = db->select_one('SELECT COUNT(*) AS c FROM comments WHERE entry_id = ?', $entry->{id});
        push @$entries, $entry;
    }
    mark_footprint($owner->{id});
    my $locals = {
        owner => $owner,
        entries => $entries,
        myself => (current_user()->{id} == $owner->{id}),
    };
    $c->render('entries.tx', $locals);
};

get '/diary/entry/:entry_id' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $entry_id = $c->args->{entry_id};
    my $entry = db->select_row('SELECT * FROM entries WHERE id = ?', $entry_id);
    abort_content_not_found() if (!$entry);
    my ($title, $content) = split(/\n/, $entry->{body}, 2);
    $entry->{title} = $title;
    $entry->{content} = $content;
    $entry->{is_private} = ($entry->{private} == 1);
    my $owner = get_user($entry->{user_id});
    if ($entry->{is_private} && !permitted($owner->{id})) {
        abort_permission_denied();
    }
    my $comments = [];
    for my $comment (@{db->select_all('SELECT * FROM comments WHERE entry_id = ?', $entry->{id})}) {
        push @$comments, set_user_names($comment, get_user($comment->{user_id}));
    }
    mark_footprint($owner->{id});
    my $locals = {
        'owner' => $owner,
        'entry' => $entry,
        'comments' => $comments,
    };
    $c->render('entry.tx', $locals);
};

post '/diary/entry' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $query = 'INSERT INTO entries (user_id, private, body) VALUES (?,?,?)';
    my $title = $c->req->param('title');
    my $content = $c->req->param('content');
    my $private = $c->req->param('private');
    my $body = ($title || "タイトルなし") . "\n" . $content;
    db->query($query, current_user()->{id}, ($private ? '1' : '0'), $body);
    redirect('/diary/entries/'.current_user()->{account_name});
};

post '/diary/comment/:entry_id' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $entry_id = $c->args->{entry_id};
    my $entry = db->select_row('SELECT * FROM entries WHERE id = ?', $entry_id);
    abort_content_not_found() if (!$entry);
    $entry->{is_private} = ($entry->{private} == 1);
    if ($entry->{is_private} && !permitted($entry->{user_id})) {
        abort_permission_denied();
    }
    my $query = 'INSERT INTO comments (entry_id, user_id, comment) VALUES (?,?,?)';
    my $comment = $c->req->param('comment');
    db->query($query, $entry->{id}, current_user()->{id}, $comment);
    redirect('/diary/entry/'.$entry->{id});
};

get '/footprints' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $query = 'SELECT owner_id, created_at AS updated FROM footprints WHERE user_id = ? ORDER BY id DESC LIMIT 50';
    my $footprints = [];
    for my $fp (@{db->select_all($query, current_user()->{id})}) {
        push @$footprints, set_user_names($fp, get_user($fp->{owner_id}));
    }
    $c->render('footprints.tx', { footprints => $footprints });
};

get '/friends' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $query = 'SELECT * FROM relations WHERE one = ? ORDER BY id DESC';
    my $friends = [];
    for my $rel (@{db->select_all($query, current_user()->{id})}) {
        push @$friends, set_user_names($rel, get_user($rel->{another}));
    }
    $c->render('friends.tx', { friends => $friends });
};

post '/friends/:account_name' => [qw(set_global authenticated)] => sub {
    my ($self, $c) = @_;
    my $account_name = $c->args->{account_name};
    if (!is_friend_account($account_name)) {
        my $user = user_from_account($account_name);
        abort_content_not_found() if (!$user);
        db->query('INSERT INTO relations (one, another) VALUES (?,?), (?,?)', current_user()->{id}, $user->{id}, $user->{id}, current_user()->{id});
        db->query('UPDATE profiles SET friends = friends + 1 WHERE user_id IN (?,?)', current_user()->{id}, $user->{id});
        redirect('/friends');
    }
};

get '/initialize' => sub {
    my ($self, $c) = @_;
    db->query("DELETE FROM relations WHERE id > 500000");
    db->query("DELETE FROM footprints WHERE id > 500000");
    db->query("DELETE FROM entries WHERE id > 500000");
    db->query("DELETE FROM comments WHERE id > 1500000");
    db->query(<<SQL);
UPDATE profiles p
JOIN (SELECT one, COUNT(*) AS friends FROM relations GROUP BY one) r
ON p.user_id = r.one SET p.friends = r.friends
SQL
};

1;

__END__

ALTER TABLE profiles ADD COLUMN friends int AFTER pref;
ALTER TABLE relations ADD INDEX friendlist (one);
ALTER TABLE comments ADD INDEX user_id (user_id), DROP INDEX created_at;
ALTER TABLE entries DROP INDEX created_at;

CREATE TABLE fp LIKE footprints;
ALTER TABLE fp ADD COLUMN date date NOT NULL, ADD UNIQUE INDEX unique_per_day (user_id,owner_id,date), ADD INDEX user_id (user_id);
REPLACE INTO fp SELECT id, user_id, owner_id, created_at, DATE(created_at) FROM footprints WHERE id <= 500000;
RENAME TABLE footprints TO footprints_old, fp TO footprints;

-- /etc/mysql/mysql.conf.d/mysqld.cnf
[mysqld]
performance_schema = OFF
transaction_isolation = READ-COMMITTED

innodb_strict_mode
innodb_file_format = Barracuda
innodb_autoinc_lock_mode = 2

innodb_buffer_pool_size = 2G
innodb_log_file_size = 128M
innodb_flush_log_at_trx_commit = 0
innodb_doublewrite = 0

innodb_buffer_pool_dump_at_shutdown
innodb_buffer_pool_load_at_startup
