-- Table structure for table `longqa`
CREATE TABLE IF NOT EXISTS `Longqa` (
  `longqa_qid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `test_id` TEXT NOT NULL,
  `qid` TEXT NOT NULL,
  `q` TEXT NOT NULL,
  `marks` INTEGER DEFAULT NULL,
  `uid` INTEGER DEFAULT NULL
);

-- Table structure for table `longtest`
CREATE TABLE IF NOT EXISTS `Longtest` (
  `longtest_qid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `email` TEXT NOT NULL,
  `test_id` TEXT NOT NULL,
  `qid` INTEGER NOT NULL,
  `ans` TEXT NOT NULL,
  `marks` INTEGER NOT NULL,
  `uid` INTEGER NOT NULL
);

-- Table structure for table `practicalqa`
CREATE TABLE IF NOT EXISTS `Practicalqa` (
  `pracqa_qid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `test_id` TEXT NOT NULL,
  `qid` TEXT NOT NULL,
  `q` TEXT NOT NULL,
  `compiler` INTEGER NOT NULL,
  `marks` INTEGER NOT NULL,
  `uid` INTEGER NOT NULL
);

-- Table structure for table `practicaltest`
CREATE TABLE IF NOT EXISTS `Practicaltest` (
  `pid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `email` TEXT NOT NULL,
  `test_id` TEXT NOT NULL,
  `qid` TEXT NOT NULL,
  `code` TEXT,
  `input` TEXT,
  `executed` TEXT DEFAULT NULL,
  `marks` INTEGER NOT NULL,
  `uid` INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS `Proctoring_log` (
  `pid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `email` TEXT NOT NULL,
  `name` TEXT NOT NULL,
  `test_id` TEXT NOT NULL,
  `voice_db` INTEGER DEFAULT '0',
  `img_log` TEXT NOT NULL,
  `user_movements_updown` INTEGER NOT NULL,
  `user_movements_lr` INTEGER NOT NULL,
  `user_movements_eyes` INTEGER NOT NULL,
  `phone_detection` INTEGER NOT NULL,
  `person_status` INTEGER NOT NULL,
  `log_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `uid` INTEGER NOT NULL
);


-- Table structure for table `questions`
CREATE TABLE IF NOT EXISTS `Questions` (
  `questions_uid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `test_id` TEXT NOT NULL,
  `qid` TEXT NOT NULL,
  `q` TEXT NOT NULL,
  `a` TEXT NOT NULL,
  `b` TEXT NOT NULL,
  `c` TEXT NOT NULL,
  `d` TEXT NOT NULL,
  `ans` TEXT NOT NULL,
  `marks` INTEGER NOT NULL,
  `uid` INTEGER NOT NULL
);

-- Table structure for table `students`
CREATE TABLE IF NOT EXISTS `Students` (
  `sid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `email` TEXT NOT NULL,
  `test_id` TEXT NOT NULL,
  `qid` TEXT DEFAULT NULL,
  `ans` TEXT,
  `uid` INTEGER NOT NULL
);

-- Table structure for table `studenttestinfo`
CREATE TABLE IF NOT EXISTS `Studenttestinfo` (
  `stiid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `email` TEXT NOT NULL,
  `test_id` TEXT NOT NULL,
  `time_left` TEXT NOT NULL,
  `completed` INTEGER DEFAULT '0',
  `uid` INTEGER NOT NULL
);


-- Table structure for table `teachers`
CREATE TABLE IF NOT EXISTS `Teachers` (
  `tid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `email` TEXT NOT NULL,
  `test_id` TEXT NOT NULL,
  `test_type` TEXT NOT NULL,
  `start` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `end` TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  `duration` INTEGER NOT NULL,
  `show_ans` INTEGER NOT NULL,
  `password` TEXT NOT NULL,
  `subject` TEXT NOT NULL,
  `topic` TEXT NOT NULL,
  `neg_marks` INTEGER NOT NULL,
  `calc` INTEGER NOT NULL,
  `proctoring_type` INTEGER NOT NULL DEFAULT '0',
  `uid` INTEGER NOT NULL
);

-- Table structure for table `users`
CREATE TABLE IF NOT EXISTS `Users` (
  `uid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `name` TEXT NOT NULL,
  `email` TEXT NOT NULL,
  `password` TEXT NOT NULL,
  `register_time` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `user_type` TEXT NOT NULL,
  `user_image` TEXT NOT NULL,
  `user_login` INTEGER NOT NULL,
  `examcredits` INTEGER NOT NULL DEFAULT '7'
);
