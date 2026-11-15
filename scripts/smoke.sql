INSERT INTO roster (school_id, id, record_type, first_name, last_name, name_key, class_name, stream, gender, student_id, extra_detail, subjects_json, classes_json)
VALUES ('s1', 'a1', 'student', 'A', 'B', 'a|b', 'P1', '', '', '', '', '[]', '[]')
ON CONFLICT(school_id, id) DO UPDATE SET first_name = excluded.first_name;

INSERT INTO roster (school_id, id, record_type, first_name, last_name, name_key, class_name, stream, gender, student_id, extra_detail, subjects_json, classes_json)
VALUES ('s1', 'a1', 'student', 'A', 'B', 'a|b', 'P1', '', '', '', '', '[]', '[]')
ON CONFLICT(school_id, id) DO UPDATE SET first_name = excluded.first_name;
