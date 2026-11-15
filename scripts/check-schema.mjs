import fs from 'fs';

const required = {
  roster: ['school_id','id','record_type','first_name','last_name','name_key','class_name','stream','gender','student_id','extra_detail','subjects_json','classes_json','batch_id','cloudinary_url','created_by','created_at','updated_at','updated_by'],
  roster_batches: ['school_id','id','record_type','class_name','stream','uploaded_by','uploaded_at','file_name','file_size','sheet_name','total_rows','header_row_index','status','created_count','updated_count','unchanged_count','rejected_count','last_processed_offset','cloudinary_url','completed_at'],
  class_structure: ['school_id','class_name','stream','student_count'],
  class_subjects: ['school_id','class_name','subject','student_count'],
  school_settings: ['school_id','teacher_access_mode'],
  teacher_assignments: ['school_id','uid','class_name','stream'],
};

const data = JSON.parse(fs.readFileSync(0, 'utf8'));
const rows = (Array.isArray(data) ? data[0] : data).results || [];

const have = {};
for (const r of rows) (have[r.tbl] ||= new Set()).add(r.col);

let bad = false;
for (const [table, cols] of Object.entries(required)) {
  if (!have[table]) {
    console.error(`MISSING TABLE: ${table}`);
    bad = true;
    continue;
  }
  for (const c of cols) {
    if (!have[table].has(c)) {
      console.error(`MISSING COLUMN: ${table}.${c}`);
      bad = true;
    }
  }
}

if (bad) process.exit(1);
console.log('Schema check passed.');
