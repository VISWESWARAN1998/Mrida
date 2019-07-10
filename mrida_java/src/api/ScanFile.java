/*
 * SWAMI KARUPPASWAMI THUNNAI
 * 
 * @author VISWESWARAN NAGASIVAM
 */

package api;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

/**
 * Used to scan a specific file
 * @author Visweswaran
 */
public class ScanFile extends Thread{
    
    private String fileLocation;
    private JTable table;
    
    public ScanFile(String fileLocation, JTable table)
    {
        this.fileLocation = fileLocation;
        this.table = table;
    }
    
    public void run()
    {
        DefaultTableModel model = (DefaultTableModel) table.getModel();
        try 
        {
            Document document = Jsoup.connect("http://127.0.0.1:5660/scan_file_for_yara").ignoreContentType(true).data("target", "all").data("file", this.fileLocation).post();
            JSONObject object = (JSONObject) new JSONParser().parse(document.text());
            boolean result = (boolean) object.get("message");
            if(result)
            {
                JSONArray array = (JSONArray) object.get("detections");
                for(Object o: array)
                {
                    JSONObject detection = (JSONObject) o;
                    model.addRow(new Object[]{this.fileLocation, detection.get("name"), detection.get("author"), detection.get("description")});
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(ScanFile.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ParseException ex) {
            Logger.getLogger(ScanFile.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
